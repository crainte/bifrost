-module(bifrost_threat_campaigns).

%% Campaign grouping and expiring review suppressions for the Threats queue.
%%
%% A campaign is a set of generated hostnames that share a marker first label
%% and TLD, e.g. 447.<anything>.site or 1xx.<anything>.site. Suppressions are
%% review-only: they keep the analyzer from re-queueing matching traffic, and
%% never touch DNS allow/block policy. They expire so a recurring campaign is
%% surfaced again instead of being hidden forever.

-export([campaign_key/1, group/1, validate_dismissal/1,
         list/0, dismiss/1, revoke/1, suppressed_sql/2]).

-define(MIN_DOMAINS, 3).
-define(DEFAULT_DAYS, 30).
-define(MAX_DAYS, 365).

campaign_key(Domain) when is_binary(Domain) ->
    Lower = string:lowercase(Domain),
    case bifrost_api_handler:threat_eligible_domain(Lower) of
        false -> none;
        true ->
            case binary:split(Lower, <<".">>, [global]) of
                [Label, _, _ | _] = Parts ->
                    case valid_label(Label) of
                        true -> {lists:last(Parts), Label};
                        false -> none
                    end;
                _ -> none
            end
    end;
campaign_key(_) -> none.

%% Candidates: [#{domain, score, hits}]. Only groups large enough to be a
%% pattern are returned; singletons stay ordinary per-domain review items.
group(Candidates) ->
    Groups = lists:foldl(fun(#{domain := D} = C, Acc) ->
        case campaign_key(D) of
            none -> Acc;
            Key -> maps:update_with(Key, fun(L) -> [C | L] end, [C], Acc)
        end
    end, #{}, Candidates),
    Campaigns = [campaign(Tld, Label, Members)
                 || {{Tld, Label}, Members} <- maps:to_list(Groups),
                    length(Members) >= ?MIN_DOMAINS],
    lists:sort(fun(A, B) ->
        {maps:get(domain_count, A), maps:get(queries, A)} >=
            {maps:get(domain_count, B), maps:get(queries, B)}
    end, Campaigns).

campaign(Tld, Label, Members) ->
    Sorted = lists:sort(fun(A, B) -> maps:get(hits, A) >= maps:get(hits, B) end, Members),
    #{tld => Tld, leading_label => Label,
      pattern => <<Label/binary, ".*.", Tld/binary>>,
      domain_count => length(Members),
      queries => lists:sum([maps:get(hits, M) || M <- Members]),
      max_score => lists:max([maps:get(score, M) || M <- Members]),
      domains => [maps:get(domain, M) || M <- Sorted]}.

validate_dismissal(#{<<"tld">> := Tld0, <<"leading_label">> := Label0} = Body)
  when is_binary(Tld0), is_binary(Label0) ->
    Tld = string:lowercase(Tld0),
    Label = string:lowercase(Label0),
    Days = maps:get(<<"days">>, Body, ?DEFAULT_DAYS),
    Client = case maps:get(<<"client_ip">>, Body, null) of
        null -> {ok, null};
        <<>> -> {ok, null};
        Ip -> parse_ip(Ip)
    end,
    case {valid_tld(Tld), valid_label(Label), valid_days(Days), Client} of
        {true, true, true, {ok, ClientIp}} ->
            {ok, #{tld => Tld, leading_label => Label, client_ip => ClientIp, days => Days}};
        {false, _, _, _} -> {error, <<"invalid tld">>};
        {_, false, _, _} -> {error, <<"invalid leading_label">>};
        {_, _, false, _} -> {error, <<"days must be 1-365">>};
        _ -> {error, <<"invalid client_ip">>}
    end;
validate_dismissal(_) ->
    {error, <<"missing tld or leading_label">>}.

list() ->
    Pending = case bifrost_db_pool:equery(
            "SELECT domain, score, hits FROM suspicious_candidates WHERE status = 'pending'", []) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{domain => D, score => S, hits => H} || {D, S, H} <- Rows];
        _ -> []
    end,
    #{campaigns => [C#{clients => clients(maps:get(domains, C))} || C <- group(Pending)],
      suppressions => active_suppressions()}.

dismiss(#{tld := Tld, leading_label := Label, client_ip := Client, days := Days}) ->
    Sql = "WITH dismissed AS ("
          "  UPDATE suspicious_candidates c SET status = 'dismissed', updated_at = now() "
          "  WHERE c.status = 'pending' "
          "    AND split_part(lower(c.domain), '.', 1) = $2 "
          "    AND right(lower(c.domain), length($1::text) + 1) = '.' || $1::text "
          "    AND array_length(string_to_array(c.domain, '.'), 1) >= 3 "
          "    AND ($3::inet IS NULL OR ("
          "      EXISTS (SELECT 1 FROM query_log q WHERE q.domain = c.domain AND q.client_ip = $3::inet) "
          "      AND NOT EXISTS (SELECT 1 FROM query_log q WHERE q.domain = c.domain AND q.client_ip <> $3::inet))) "
          "  RETURNING 1) "
          "INSERT INTO threat_suppressions "
          "  (tld, leading_label, client_ip, expires_at, matched_domains) "
          "SELECT $1, $2, $3::inet, now() + make_interval(days => $4::int), "
          "  (SELECT count(*) FROM dismissed) "
          "RETURNING id, matched_domains, "
          "  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    case bifrost_db_pool:equery(Sql, [Tld, Label, Client, Days]) of
        {ok, 1, _, [{Id, Matched, Expires}]} ->
            {ok, #{id => Id, dismissed => Matched, expires_at => Expires}};
        Error -> {error, Error}
    end.

revoke(Id) when is_integer(Id), Id > 0 ->
    case bifrost_db_pool:equery(
            "UPDATE threat_suppressions SET revoked_at = now() "
            "WHERE id = $1 AND revoked_at IS NULL", [Id]) of
        {ok, 1} -> ok;
        {ok, 0} -> {error, not_found};
        Error -> {error, Error}
    end;
revoke(_) -> {error, not_found}.

%% SQL predicate: true when the query_log row is covered by an active
%% suppression. Client-scoped rules hide only that client's traffic.
suppressed_sql(DomainExpr, ClientExpr) ->
    "EXISTS (SELECT 1 FROM threat_suppressions s "
    "WHERE s.revoked_at IS NULL AND s.expires_at > now() "
    "  AND (s.client_ip IS NULL OR s.client_ip = " ++ ClientExpr ++ ") "
    "  AND split_part(lower(" ++ DomainExpr ++ "), '.', 1) = s.leading_label "
    "  AND right(lower(" ++ DomainExpr ++ "), length(s.tld) + 1) = '.' || s.tld "
    "  AND array_length(string_to_array(" ++ DomainExpr ++ ", '.'), 1) >= 3)".

clients([]) -> [];
clients(Domains) ->
    case bifrost_db_pool:equery(
            "SELECT client_ip, count(*) FROM query_log WHERE domain = ANY($1::text[]) "
            "GROUP BY client_ip ORDER BY count(*) DESC, client_ip LIMIT 5", [Domains]) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{ip => ip_bin(Ip), queries => N} || {Ip, N} <- Rows];
        _ -> []
    end.

active_suppressions() ->
    case bifrost_db_pool:equery(
            "SELECT id, tld, leading_label, client_ip, matched_domains, "
            "  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
            "  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
            "FROM threat_suppressions WHERE revoked_at IS NULL AND expires_at > now() "
            "ORDER BY expires_at", []) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{id => Id, tld => Tld, leading_label => Label,
               pattern => <<Label/binary, ".*.", Tld/binary>>,
               client_ip => case Ip of null -> null; _ -> ip_bin(Ip) end,
               matched_domains => Matched, created_at => Created, expires_at => Expires}
             || {Id, Tld, Label, Ip, Matched, Created, Expires} <- Rows];
        _ -> []
    end.

valid_tld(T) -> re:run(T, "^[a-z0-9-]{2,63}$", [{capture, none}]) =:= match.
valid_label(L) ->
    byte_size(L) =< 63 andalso re:run(L, "^[0-9]+x*$", [{capture, none}]) =:= match.
valid_days(D) -> is_integer(D) andalso D >= 1 andalso D =< ?MAX_DAYS.

parse_ip(Ip) when is_binary(Ip) ->
    case inet:parse_address(binary_to_list(Ip)) of
        {ok, T} -> {ok, T};
        _ -> error
    end;
parse_ip(_) -> error.

ip_bin(Ip) when is_tuple(Ip) -> list_to_binary(inet:ntoa(Ip));
ip_bin(Ip) -> Ip.

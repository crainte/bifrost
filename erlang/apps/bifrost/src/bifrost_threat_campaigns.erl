-module(bifrost_threat_campaigns).

%% Campaign grouping and expiring review suppressions for the Threats queue.
%%
%% A campaign is a set of generated hostnames with an enumerated first label,
%% in one of two shapes (see group/1): a FAMILY of siblings under one parent,
%% {n}.stg.content-loader.com, or a MARKER label shared across distinct
%% registrable domains of one TLD, 447.<anything>.site. Suppressions are
%% review-only: they keep the analyzer from re-queueing matching traffic, and
%% never touch DNS allow/block policy. They expire so a recurring campaign is
%% surfaced again instead of being hidden forever.

-export([classify/1, group/1, validate_dismissal/1,
         list/0, dismiss/1, revoke/1, suppressed_sql/2]).

-define(MIN_DOMAINS, 3).
-define(DEFAULT_DAYS, 30).
-define(MAX_DAYS, 365).

%% {enumerated, Parent, Label, Tld, Base} for an eligible name whose first label
%% is enumerated (^[0-9]+x*$) under a parent of 2+ labels, e.g.
%% 3.stg.content-loader.com -> parent stg.content-loader.com, label 3, tld com,
%% registrable content-loader.com. Every other name is `none`. group/1 decides
%% from these whether a name belongs to a family or a marker campaign.
classify(Domain) when is_binary(Domain) ->
    Lower = string:lowercase(Domain),
    case bifrost_api_handler:threat_eligible_domain(Lower) of
        false -> none;
        true ->
            case binary:split(Lower, <<".">>, [global]) of
                [Label, _, _ | _] = Parts ->
                    case valid_label(Label) of
                        true ->
                            {enumerated, join(tl(Parts)), Label,
                             lists:last(Parts), bifrost_api_handler:extract_base_domain(Lower)};
                        false -> none
                    end;
                _ -> none
            end
    end;
classify(_) -> none.

%% Candidates: [#{domain, score, hits}]. Two shapes, families first:
%%
%%  family  {n}.<parent> — >= ?MIN_DOMAINS enumerated siblings under ONE parent.
%%          0..9.stg.content-loader.com is one campaign, not ten.
%%  marker  <label>.*.<tld> — the same marker label across >= ?MIN_DOMAINS
%%          DISTINCT registrable domains (447.alpha.site, 447.beta.site, ...),
%%          built only from names no family claimed. Distinct registrable
%%          domains, because 1.pool.ntp.org, 1.cn.pool.ntp.org and
%%          1.datadog.pool.ntp.org are one operator's shards, not a campaign;
%%          and family members are excluded so 0.gravatar.com cannot borrow
%%          0.gifteddonut.com from a real family to make "0.*.com".
%%
%% Singletons stay ordinary per-domain review items.
group(Candidates) ->
    Classified = [{classify(D), C} || #{domain := D} = C <- Candidates],
    ByParent = lists:foldl(fun
        ({{enumerated, Parent, _, _, _}, C}, Acc) ->
            maps:update_with(Parent, fun(L) -> [C | L] end, [C], Acc);
        (_, Acc) -> Acc
    end, #{}, Classified),
    Families = maps:filter(fun(_, Ms) -> length(Ms) >= ?MIN_DOMAINS end, ByParent),
    Markers = lists:foldl(fun
        ({{enumerated, Parent, Label, Tld, Base}, C}, Acc) when not is_map_key(Parent, Families) ->
            maps:update_with({Tld, Label}, fun(L) -> [{Base, C} | L] end, [{Base, C}], Acc);
        (_, Acc) -> Acc
    end, #{}, Classified),
    Campaigns =
        [campaign(#{kind => family, parent => P, tld => last_label(P), leading_label => null,
                    pattern => <<"{n}.", P/binary>>}, Ms)
         || {P, Ms} <- maps:to_list(Families)] ++
        [campaign(#{kind => marker, parent => null, tld => Tld, leading_label => Label,
                    pattern => <<Label/binary, ".*.", Tld/binary>>}, [C || {_, C} <- Ms])
         || {{Tld, Label}, Ms} <- maps:to_list(Markers),
            length(lists:usort([B || {B, _} <- Ms])) >= ?MIN_DOMAINS],
    lists:sort(fun(A, B) ->
        {maps:get(domain_count, A), maps:get(queries, A)} >=
            {maps:get(domain_count, B), maps:get(queries, B)}
    end, Campaigns).

campaign(Base, Members) ->
    Sorted = lists:sort(fun(A, B) -> maps:get(hits, A) >= maps:get(hits, B) end, Members),
    Base#{domain_count => length(Members),
          queries => lists:sum([maps:get(hits, M) || M <- Members]),
          max_score => lists:max([maps:get(score, M) || M <- Members]),
          domains => [maps:get(domain, M) || M <- Sorted]}.

%% `kind` defaults to marker, so a client that predates families keeps working.
validate_dismissal(Body) when is_map(Body) ->
    Days = maps:get(<<"days">>, Body, ?DEFAULT_DAYS),
    Client = case maps:get(<<"client_ip">>, Body, null) of
        null -> {ok, null};
        <<>> -> {ok, null};
        Ip -> parse_ip(Ip)
    end,
    case {pattern(Body), valid_days(Days), Client} of
        {{ok, Pattern}, true, {ok, ClientIp}} ->
            {ok, Pattern#{client_ip => ClientIp, days => Days}};
        {{error, _} = E, _, _} -> E;
        {_, false, _} -> {error, <<"days must be 1-365">>};
        _ -> {error, <<"invalid client_ip">>}
    end;
validate_dismissal(_) ->
    {error, <<"missing tld or leading_label">>}.

pattern(#{<<"kind">> := <<"family">>} = Body) ->
    case bifrost_domain:normalize(maps:get(<<"parent">>, Body, null)) of
        {ok, P} ->
            case length(binary:split(P, <<".">>, [global])) >= 2
                 andalso bifrost_api_handler:threat_eligible_domain(P)
                 andalso valid_tld(last_label(P)) of
                true -> {ok, #{kind => family, parent => P, tld => last_label(P),
                               leading_label => null}};
                false -> {error, <<"invalid parent">>}
            end;
        error -> {error, <<"invalid parent">>}
    end;
pattern(#{<<"kind">> := Kind}) when Kind =/= <<"marker">> ->
    {error, <<"invalid kind">>};
pattern(#{<<"tld">> := Tld0, <<"leading_label">> := Label0})
  when is_binary(Tld0), is_binary(Label0) ->
    Tld = string:lowercase(Tld0),
    Label = string:lowercase(Label0),
    case {valid_tld(Tld), valid_label(Label)} of
        {true, true} -> {ok, #{kind => marker, parent => null, tld => Tld,
                               leading_label => Label}};
        {false, _} -> {error, <<"invalid tld">>};
        {_, false} -> {error, <<"invalid leading_label">>}
    end;
pattern(_) ->
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

%% $1 tld, $2 leading_label (marker), $3 client, $4 days, $5 kind, $6 parent.
dismiss(#{kind := Kind, tld := Tld, leading_label := Label, parent := Parent,
          client_ip := Client, days := Days}) ->
    Sql = "WITH dismissed AS ("
          "  UPDATE suspicious_candidates c SET status = 'dismissed', updated_at = now() "
          "  WHERE c.status = 'pending' "
          "    AND " ++ match_sql("c.domain", "$5::text", "$1::text", "$2::text", "$6::text") ++
          "    AND ($3::inet IS NULL OR ("
          "      EXISTS (SELECT 1 FROM query_log q WHERE q.domain = c.domain AND q.client_ip = $3::inet) "
          "      AND NOT EXISTS (SELECT 1 FROM query_log q WHERE q.domain = c.domain AND q.client_ip <> $3::inet))) "
          "  RETURNING 1) "
          "INSERT INTO threat_suppressions "
          "  (kind, tld, leading_label, parent, client_ip, expires_at, matched_domains) "
          "SELECT $5, $1, $2, $6, $3::inet, now() + make_interval(days => $4::int), "
          "  (SELECT count(*) FROM dismissed) "
          "RETURNING id, matched_domains, "
          "  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    case bifrost_db_pool:equery(Sql, [Tld, Label, Client, Days, atom_to_binary(Kind),
                                      Parent]) of
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
    "  AND " ++ match_sql(DomainExpr, "s.kind", "s.tld", "s.leading_label", "s.parent") ++ ")".

%% The ONE SQL definition of "this name matches this pattern", used both to
%% dismiss the queued names and to hide future traffic, so the two can never
%% disagree about what a suppression covers.
%%   marker: first label = label, ends in .tld, 3+ labels
%%   family: first label enumerated, and everything after it = parent exactly
match_sql(D, Kind, Tld, Label, Parent) ->
    "((" ++ Kind ++ " = 'marker' "
    "   AND split_part(lower(" ++ D ++ "), '.', 1) = " ++ Label ++ " "
    "   AND right(lower(" ++ D ++ "), length(" ++ Tld ++ ") + 1) = '.' || " ++ Tld ++ " "
    "   AND array_length(string_to_array(" ++ D ++ ", '.'), 1) >= 3) "
    " OR (" ++ Kind ++ " = 'family' "
    "   AND split_part(lower(" ++ D ++ "), '.', 1) ~ '^[0-9]+x*$' "
    "   AND substr(lower(" ++ D ++ "), length(split_part(" ++ D ++ ", '.', 1)) + 2) = "
    ++ Parent ++ ")) ".

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
            "SELECT id, kind, tld, leading_label, parent, client_ip, matched_domains, "
            "  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
            "  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
            "FROM threat_suppressions WHERE revoked_at IS NULL AND expires_at > now() "
            "ORDER BY expires_at", []) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{id => Id, kind => Kind, tld => Tld, leading_label => Label, parent => Parent,
               pattern => case Kind of
                   <<"family">> -> <<"{n}.", Parent/binary>>;
                   _ -> <<Label/binary, ".*.", Tld/binary>>
               end,
               client_ip => case Ip of null -> null; _ -> ip_bin(Ip) end,
               matched_domains => Matched, created_at => Created, expires_at => Expires}
             || {Id, Kind, Tld, Label, Parent, Ip, Matched, Created, Expires} <- Rows];
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

last_label(Name) -> lists:last(binary:split(Name, <<".">>, [global])).

join(Labels) -> iolist_to_binary(lists:join(<<".">>, Labels)).
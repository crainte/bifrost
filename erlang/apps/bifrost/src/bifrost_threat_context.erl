-module(bifrost_threat_context).

%% Contextual threat signals: evidence about a domain that its NAME cannot
%% carry. Lexical scoring (bifrost_api_handler:score_domain/1) cannot tell
%% 3.pool.ntp.org from 3.ads-cdn.example; how the network uses the name can.
%%
%%   cname_to_blocked:<target>  +3, counts as TWO signals. The domain's answers
%%                              (query_log.response_records) CNAME into a name
%%                              an enabled blocklist or manual block covers:
%%                              CNAME cloaking, a tracker behind a first-party
%%                              name. The blocklists have already vouched for
%%                              the target, hence the double weight.
%%   blocked_sibling            +2. Another child of the same parent is manually
%%                              blocked or was blocked from the Threats page, so
%%                              operator decisions carry over to the family.
%%   newly_seen                 +1. First query within ?NEW_DAYS. Only once
%%                              query_log holds ?HISTORY_DAYS of history: on a
%%                              fresh install, or just after a retention drop,
%%                              EVERY domain would look new.
%%   widespread                 -2. Queried by at least
%%                              max(?WIDESPREAD_FLOOR, ?WIDESPREAD_SHARE of the
%%                              window's active clients). Shared infrastructure
%%                              (NTP, OS updates, CDNs) without a curated list.
%%                              Negative, so never a signal (qualifies/1).
%%   single_client              tag only: one device using one app is not
%%                              evidence of anything on its own.
%%
%% One batch call per scan: a fixed number of queries whatever the number of
%% domains. Runs on the analyzer's scan worker or a per-client scan request,
%% never on the DNS path. Any failure yields no context (#{}), never a crash:
%% context only refines the lexical score, it must not stop a scan.

-export([signals/2]).
%% Pure helpers, exported for tests.
-export([suffixes/1, parent/1, widespread_threshold/1, history_sufficient/1,
         match_list/2, combine/1]).

-define(CNAME_SCORE, 3).
-define(SIBLING_SCORE, 2).
-define(NEW_SCORE, 1).
-define(WIDESPREAD_SCORE, -2).
-define(WIDESPREAD_FLOOR, 5).
-define(WIDESPREAD_SHARE, 0.25).
-define(NEW_DAYS, 7).
-define(HISTORY_DAYS, 30).
-define(MAX_CNAME_TAGS, 3).
-define(LIST_TIMEOUT, 30000).

-type ctx() :: #{score := integer(), reasons := [binary()], clients := non_neg_integer()}.

-spec signals([binary()], pos_integer()) -> #{binary() => ctx()}.
signals([], _Hours) ->
    #{};
signals(Domains0, Hours) ->
    Domains = lists:usort(Domains0),
    try
        H = integer_to_list(Hours),
        {Clients, Active} = clients(Domains, H),
        Cnames = cname_targets(Domains, H),
        Blocked = blocked_targets(lists:usort(lists:append(maps:values(Cnames)))),
        Siblings = blocked_siblings(Domains),
        New = newly_seen(Domains),
        Threshold = widespread_threshold(Active),
        maps:from_list(
          [{D, combine(#{clients => maps:get(D, Clients, 0),
                         widespread_threshold => Threshold,
                         blocked_cnames => [T || T <- maps:get(D, Cnames, []),
                                                 maps:is_key(T, Blocked)],
                         blocked_sibling => maps:is_key(D, Siblings),
                         newly_seen => maps:is_key(D, New)})}
           || D <- Domains])
    catch Class:Reason ->
        logger:warning("threat context unavailable: ~p:~p", [Class, Reason]),
        #{}
    end.

%% Facts -> score and reasons. Pure, so the weights are unit-tested directly.
-spec combine(map()) -> ctx().
combine(F) ->
    Clients = maps:get(clients, F, 0),
    Cnames = lists:sublist(lists:usort(maps:get(blocked_cnames, F, [])), ?MAX_CNAME_TAGS),
    Wide = Clients >= maps:get(widespread_threshold, F, ?WIDESPREAD_FLOOR),
    Parts = [{Cnames =/= [], ?CNAME_SCORE, [<<"cname_to_blocked:", T/binary>> || T <- Cnames]},
             {maps:get(blocked_sibling, F, false), ?SIBLING_SCORE, [<<"blocked_sibling">>]},
             {maps:get(newly_seen, F, false), ?NEW_SCORE, [<<"newly_seen">>]},
             {Wide, ?WIDESPREAD_SCORE, [<<"widespread">>]},
             {Clients =:= 1, 0, [<<"single_client">>]}],
    #{score => lists:sum([S || {true, S, _} <- Parts]),
      reasons => lists:append([R || {true, _, R} <- Parts]),
      clients => Clients}.

-spec widespread_threshold(non_neg_integer()) -> pos_integer().
widespread_threshold(Active) ->
    max(?WIDESPREAD_FLOOR, ceil(Active * ?WIDESPREAD_SHARE)).

%% Age in days of the oldest query_log row (undefined when empty).
-spec history_sufficient(integer() | undefined | null) -> boolean().
history_sufficient(Days) ->
    is_integer(Days) andalso Days >= ?HISTORY_DAYS.

%% Label-boundary suffixes, most specific first: a.b.c -> [a.b.c, b.c, c].
%% The same walk Rust's blocklist matcher does.
-spec suffixes(binary()) -> [binary()].
suffixes(Domain) ->
    Labels = binary:split(Domain, <<".">>, [global, trim_all]),
    [join(lists:nthtail(N, Labels)) || N <- lists:seq(0, length(Labels) - 1)].

%% Everything after the first label, if that is still a registrable-looking
%% name (two labels or more): 3.gifteddonut.com -> gifteddonut.com.
-spec parent(binary()) -> binary() | none.
parent(Domain) ->
    case binary:split(Domain, <<".">>, [global, trim_all]) of
        [_, _, _ | _] = Labels -> join(tl(Labels));
        _ -> none
    end.

%% Match one list's entries against the suffixes of a small target set.
%% SufMap :: #{Suffix => [Target]}. Returns the targets this list blocks, with
%% Rust's semantics: blocked if any suffix is listed, unless a `@@` exception
%% of the SAME list covers any suffix. One pass over the entries with lookups
%% into the tiny map, so nothing proportional to the list is built.
-spec match_list([binary()], #{binary() => [binary()]}) -> #{binary() => true}.
match_list(Entries, SufMap) ->
    {Blk, Exc} = lists:foldl(fun
        (<<"@@", E/binary>>, {B, X}) ->
            case SufMap of #{E := Ts} -> {B, add(Ts, X)}; _ -> {B, X} end;
        (E, {B, X}) ->
            case SufMap of #{E := Ts} -> {add(Ts, B), X}; _ -> {B, X} end
    end, {#{}, #{}}, Entries),
    maps:without(maps:keys(Exc), Blk).

%% ── queries ───────────────────────────────────────────────────

clients(Domains, H) ->
    PerDomain = case bifrost_db_pool:equery(
            "SELECT domain, count(DISTINCT client_ip)::int FROM query_log "
            "WHERE queried_at > now() - ($2 || ' hours')::interval "
            "  AND domain = ANY($1::text[]) GROUP BY domain", [Domains, H]) of
        {ok, _, Rows} -> maps:from_list(Rows);
        Err -> error({clients, Err})
    end,
    Active = case bifrost_db_pool:equery(
            "SELECT count(DISTINCT client_ip)::int FROM query_log "
            "WHERE queried_at > now() - ($1 || ' hours')::interval", [H]) of
        {ok, _, [{N}]} -> N;
        Err2 -> error({active_clients, Err2})
    end,
    {PerDomain, Active}.

%% #{Domain => [Target]}: CNAME targets seen in the domain's stored answers.
cname_targets(Domains, H) ->
    case bifrost_db_pool:equery(
            "SELECT DISTINCT q.domain, lower(rtrim(r->>'value', '.')) "
            "FROM query_log q CROSS JOIN LATERAL jsonb_array_elements("
            "  CASE WHEN jsonb_typeof(q.response_records) = 'array' "
            "       THEN q.response_records ELSE '[]'::jsonb END) r "
            "WHERE q.queried_at > now() - ($2 || ' hours')::interval "
            "  AND q.domain = ANY($1::text[]) AND r->>'rtype' = 'CNAME' "
            "  AND coalesce(r->>'value', '') <> ''", [Domains, H]) of
        {ok, _, Rows} ->
            lists:foldl(fun({D, T}, Acc) ->
                maps:update_with(D, fun(L) -> [T | L] end, [T], Acc)
            end, #{}, Rows);
        Err -> error({cname_targets, Err})
    end.

%% #{Target => true} for targets blocked by an enabled list or a manual block
%% and not allowlisted. The allowlist overrides every list, as in Rust.
blocked_targets([]) ->
    #{};
blocked_targets(Targets) ->
    SufMap = lists:foldl(fun(T, Acc) ->
        lists:foldl(fun(S, A) -> maps:update_with(S, fun(L) -> [T | L] end, [T], A) end,
                    Acc, suffixes(T))
    end, #{}, Targets),
    Suffixes = maps:keys(SufMap),
    Manual = column("SELECT domain FROM manual_blocks WHERE domain = ANY($1::text[])", Suffixes),
    Allowed = column("SELECT domain FROM allowlist WHERE domain = ANY($1::text[])", Suffixes),
    FromLists = lists:foldl(fun(Id, Acc) -> maps:merge(Acc, list_matches(Id, SufMap)) end,
                            #{}, bifrost_blocklist_manager:enabled_list_ids()),
    Blocked = maps:merge(FromLists, match_list(Manual, SufMap)),
    maps:without(maps:keys(match_list(Allowed, SufMap)), Blocked).

%% A list can hold millions of entries and reading it from Mnesia copies it, so
%% each one is matched in its own short-lived process: the copy is freed the
%% moment that process exits, and only the (tiny) match crosses back.
list_matches(Id, SufMap) ->
    {Pid, Ref} = spawn_monitor(fun() ->
        Result = case bifrost_mnesia:read_cache(Id) of
            {ok, Entries, _, _} -> match_list(Entries, SufMap);
            _ -> #{}
        end,
        exit({ok, Result})
    end),
    receive
        {'DOWN', Ref, process, Pid, {ok, Matches}} -> Matches;
        {'DOWN', Ref, process, Pid, Why} ->
            logger:warning("threat context: matching list ~p failed: ~p", [Id, Why]),
            #{}
    after ?LIST_TIMEOUT ->
        exit(Pid, kill),
        #{}
    end.

%% #{Domain => true} for domains with a blocked sibling under the same parent.
blocked_siblings(Domains) ->
    Parents = lists:usort([P || D <- Domains, P <- [parent(D)], P =/= none]),
    Blocked = case Parents of
        [] -> [];
        _ -> column("SELECT b.domain FROM (SELECT domain FROM manual_blocks "
                    "  UNION SELECT domain FROM suspicious_candidates WHERE status = 'blocked') b "
                    "WHERE strpos(b.domain, '.') > 0 "
                    "  AND substr(b.domain, strpos(b.domain, '.') + 1) = ANY($1::text[])",
                    Parents)
    end,
    ByParent = lists:foldl(fun(B, Acc) ->
        maps:update_with(parent(B), fun(L) -> [B | L] end, [B], Acc)
    end, #{}, Blocked),
    maps:from_list([{D, true} || D <- Domains,
                                 lists:any(fun(B) -> B =/= D end,
                                           maps:get(parent(D), ByParent, []))]).

%% #{Domain => true} for domains whose FIRST query is within ?NEW_DAYS. NOT
%% EXISTS on an older row, rather than min(queried_at): an established domain
%% stops at its first old row instead of reading its whole history.
newly_seen(Domains) ->
    Oldest = case bifrost_db_pool:equery(
            "SELECT (extract(epoch FROM now() - min(queried_at)) / 86400)::int FROM query_log",
            []) of
        {ok, _, [{Days}]} -> Days;
        Err -> error({history, Err})
    end,
    case history_sufficient(Oldest) of
        false -> #{};
        true ->
            New = column("SELECT d FROM unnest($1::text[]) AS d "
                         "WHERE EXISTS (SELECT 1 FROM query_log q WHERE q.domain = d) "
                         "  AND NOT EXISTS (SELECT 1 FROM query_log q WHERE q.domain = d "
                         "  AND q.queried_at <= now() - interval '"
                         ++ integer_to_list(?NEW_DAYS) ++ " days')",
                         Domains),
            maps:from_list([{D, true} || D <- New])
    end.

column(Sql, Param) ->
    case bifrost_db_pool:equery(Sql, [Param]) of
        {ok, _, Rows} -> [V || {V} <- Rows];
        Err -> error({query_failed, Err})
    end.

add(Targets, Map) ->
    lists:foldl(fun(T, M) -> M#{T => true} end, Map, Targets).

join(Labels) ->
    iolist_to_binary(lists:join(<<".">>, Labels)).

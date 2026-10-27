%% Common Test suite for the RDAP read-through cache
%% (bifrost_api_handler:rdap_cached/1,2 + bifrost_rdap), against a REAL Postgres.
%%
%% Bugs this suite exists to prevent:
%%
%%  A. enrich_with_rdap/1 (the Clients page) called the registry directly, then
%%     later synchronously on a cold cache: up to 10 live requests per page load,
%%     duplicated by concurrent loads. -> enrich_path_never_contacts_the_registry,
%%     concurrent_page_loads_fetch_once, claim_is_exclusive_across_sessions.
%%  B. Every failure was cached forever, so one 429 removed a domain from age
%%     scoring for good. -> transient_failure_is_retried_with_backoff,
%%     retry_after_is_honoured, permanent_failure_is_final.
%%  C. age_days was stored as of the lookup and never advanced, so a once-young
%%     domain kept the new_domain score and the auto-block age gate forever.
%%     -> age_is_computed_at_read.
%%  D. Cache-hit / base-domain keying / scoring totality / pool survival, as
%%     before.
%%
%% NO NETWORK: the `rdap_lookup` app env points bifrost_rdap at fake_lookup/1
%% below, which records WHICH PROCESS called it. That is how the page-path tests
%% prove the request process itself never reached a registry. ?BASE uses a TLD
%% with no rdap_server/1 entry, so there is no registry host to pace either.
%%
%% Connection is taken from env, as in bifrost_retention_SUITE:
%%   BIFROST_TEST_DB_HOST (default "postgres"), BIFROST_TEST_DB_PORT (5432),
%%   BIFROST_TEST_DB_NAME (bifrost), BIFROST_TEST_DB_USER (bifrost),
%%   BIFROST_TEST_DB_PASSWORD (bifrost).
%%
%% ISOLATION: a throwaway DATABASE, not a schema. The pool runs the real
%% migrations into it on connect, so `rdap_cache` here is the production schema
%% including migration 014 — and the live dev cache is in another database, out of
%% reach of the DELETE in init_per_testcase.
-module(bifrost_rdap_cache_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([cache_hit_never_reaches_the_registry/1,
         enrich_path_uses_the_cache_not_a_live_lookup/1,
         enrich_path_never_contacts_the_registry/1,
         concurrent_page_loads_fetch_once/1,
         claim_is_exclusive_across_sessions/1,
         transient_failure_is_retried_with_backoff/1,
         retry_after_is_honoured/1,
         permanent_failure_is_final/1,
         age_is_computed_at_read/1,
         subdomain_variants_share_one_entry/1,
         rdap_signals_are_namespaced_and_scoring_is_total/1,
         bad_parameter_type_does_not_kill_the_pool/1]).
-export([fake_lookup/1]).

%% rdap_server/1 has no entry for this, so the real lookup never makes a request.
-define(BASE, <<"nosuchregistry.invalidtld">>).
-define(CALLS, rdap_ct_calls).

all() ->
    [cache_hit_never_reaches_the_registry,
     enrich_path_uses_the_cache_not_a_live_lookup,
     enrich_path_never_contacts_the_registry,
     concurrent_page_loads_fetch_once,
     claim_is_exclusive_across_sessions,
     transient_failure_is_retried_with_backoff,
     retry_after_is_honoured,
     permanent_failure_is_final,
     age_is_computed_at_read,
     subdomain_variants_share_one_entry,
     rdap_signals_are_namespaced_and_scoring_is_total,
     bad_parameter_type_does_not_kill_the_pool].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(epgsql),
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_rdap_" ++ integer_to_list(erlang:system_time(millisecond)),
    Admin = raw_connect(Db),
    sq(Admin, "CREATE DATABASE " ++ Scratch),
    ok = epgsql:close(Admin),

    CfgPath = filename:join(?config(priv_dir, Config), "rdap_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    ok = application:set_env(bifrost, rdap_lookup, {?MODULE, fake_lookup, []}),

    %% start_link links to THIS process, which exits before the testcases run.
    {ok, CfgPid} = bifrost_config_server:start_link(),
    erlang:unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    erlang:unlink(PoolPid),
    {ok, RdapPid} = bifrost_rdap:start_link(),
    erlang:unlink(RdapPid),
    ok = wait_connected(50),
    %% Migration 014 must have landed, or every test below is asserting on a
    %% schema that does not exist in production.
    {ok, _, Cols} = pq("SELECT column_name FROM information_schema.columns "
                       "WHERE table_name = 'rdap_cache'"),
    Names = [C || {C} <- Cols],
    [?assert(lists:member(N, Names)) || N <- [<<"has_transfer_lock">>,
                                              <<"pending_delete">>,
                                              <<"privacy_protected">>,
                                              <<"registered_on">>,
                                              <<"status">>,
                                              <<"attempts">>,
                                              <<"retry_at">>]],
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    stop(bifrost_rdap),
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    application:unset_env(bifrost, rdap_lookup),
    Admin = raw_connect(?config(db, Config)),
    sq(Admin, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)"),
    ok = epgsql:close(Admin),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

%% Runs in the testcase process, so the calls table lives exactly as long as the
%% testcase does.
init_per_testcase(_Case, Config) ->
    {ok, _} = pq("DELETE FROM rdap_cache"),
    ets:new(?CALLS, [named_table, public, duplicate_bag]),
    set_lookup(fun(_) -> {final, unsupported} end),
    Config.

%% ── A: page path / dedupe ────────────────────────────────────

%% A lookup for an unsupported TLD yields all-undefined, so these values can ONLY
%% have come from the row. Deleting the cache read fails here.
cache_hit_never_reaches_the_registry(_Config) ->
    seed(?BASE, 42, false, true, true),
    ?assertEqual(#{age_days => 42,
                   has_transfer_lock => false,
                   pending_delete => true,
                   privacy_protected => true,
                   lookup => done},
                 bifrost_api_handler:rdap_cached(?BASE)),
    ?assertEqual([], calls()),
    ?assertEqual(1, row_count(?BASE)),
    ?assertEqual([<<"rdap:new_domain">>, <<"rdap:no_transfer_lock">>,
                  <<"rdap:pending_delete">>, <<"rdap:privacy_protected">>],
                 bifrost_api_handler:rdap_reasons(bifrost_api_handler:rdap_cached(?BASE))).

%% The code path the Clients page actually calls must go THROUGH the cache.
enrich_path_uses_the_cache_not_a_live_lookup(_Config) ->
    seed(?BASE, 12, false, true, true),
    Candidate = #{domain => ?BASE, score => 1, hits => 5, reasons => [<<"entropy">>]},
    [Enriched] = bifrost_api_handler:enrich_with_rdap([Candidate]),
    %% age 12d (+3) and pending_delete (+3). The two non-discriminating flags are
    %% seeded true/false here precisely to assert they add nothing.
    ?assertEqual(1 + 6, maps:get(score, Enriched)),
    ?assertEqual(#{age_days => 12, has_transfer_lock => false,
                   pending_delete => true, privacy_protected => true, lookup => done},
                 maps:get(rdap, Enriched)),
    Reasons = maps:get(reasons, Enriched),
    ?assert(lists:member(<<"entropy">>, Reasons)),
    ?assert(lists:member(<<"rdap:new_domain">>, Reasons)),
    ?assert(lists:member(<<"rdap:privacy_protected">>, Reasons)),
    ?assertEqual([], calls()),
    ?assertEqual({ok, [{?BASE}]}, all_domains()).

%% THE regression for the page-load cost. Cold cache, through the production
%% entry point: the request returns at once with `lookup => pending`, the lookup
%% happens on some OTHER process, and the next load is enriched from the row.
%% If enrich_one/1 goes back to `sync`, the caller shows up in calls().
enrich_path_never_contacts_the_registry(_Config) ->
    set_lookup(fun(_) -> timer:sleep(200), registered(12) end),
    Candidate = #{domain => ?BASE, score => 1, hits => 5, reasons => [<<"entropy">>]},
    [Cold] = bifrost_api_handler:enrich_with_rdap([Candidate]),
    ?assertEqual(1, maps:get(score, Cold)),
    ?assertEqual(pending, maps:get(lookup, maps:get(rdap, Cold))),
    ok = wait_status(?BASE, <<"ok">>),
    Callers = [P || {P, _} <- calls()],
    ?assertEqual(1, length(Callers)),
    ?assertNot(lists:member(self(), Callers)),
    [Warm] = bifrost_api_handler:enrich_with_rdap([Candidate]),
    ?assertEqual(1 + 3, maps:get(score, Warm)),
    ?assertEqual(done, maps:get(lookup, maps:get(rdap, Warm))),
    ?assertEqual(1, length(calls())),

    seed(<<"old-example.com">>, 1000, true, false, false),
    [Old] = bifrost_api_handler:enrich_with_rdap([
        #{domain => <<"www.old-example.com">>, score => 1, hits => 1, reasons => []}
    ]),
    ?assertEqual(done, maps:get(lookup, maps:get(rdap, Old))),
    %% 1000 days old: established, which discounts rather than adds.
    ?assertEqual([<<"rdap:established">>], maps:get(reasons, Old)),
    ?assertEqual(1 - 3, maps:get(score, Old)).

%% Many simultaneous page loads (and subdomain variants of the same
%% registration) on one cold domain: exactly one registry request.
concurrent_page_loads_fetch_once(_Config) ->
    set_lookup(fun(_) -> timer:sleep(300), registered(12) end),
    Variants = [?BASE, <<"ads.", (?BASE)/binary>>, <<"1.ads.", (?BASE)/binary>>],
    Parent = self(),
    Pids = [spawn_link(fun() ->
                receive go -> ok end,
                D = lists:nth(1 + (N rem length(Variants)), Variants),
                _ = bifrost_api_handler:enrich_with_rdap(
                      [#{domain => D, score => 1, hits => 1, reasons => []}]),
                Parent ! {done, self()}
            end) || N <- lists:seq(1, 20)],
    [P ! go || P <- Pids],
    [receive {done, P} -> ok after 10000 -> ct:fail(page_load_hung) end || P <- Pids],
    ok = wait_status(?BASE, <<"ok">>),
    %% Let any straggler enqueue drain before counting.
    ok = wait_idle(50),
    ?assertEqual([?BASE], [B || {_, B} <- calls()]),
    ?assertEqual({ok, [{?BASE}]}, all_domains()).

%% The cross-pod dedupe lives in ONE SQL statement, so it is tested the way two
%% pods would hit it: separate Postgres sessions, released simultaneously.
%% Dropping the WHERE on the DO UPDATE lets every session win.
claim_is_exclusive_across_sessions(Config) ->
    Db = (?config(db, Config))#{name => ?config(scratch, Config)},
    Conns = [raw_connect(Db) || _ <- lists:seq(1, 8)],
    Claim = fun(C) -> epgsql:equery(C, bifrost_rdap:claim_sql(), [?BASE]) end,
    Race = fun() ->
        Parent = self(),
        Pids = [spawn_link(fun() ->
                    receive go -> ok end,
                    Parent ! {won, self(), Claim(C)}
                end) || C <- Conns],
        [P ! go || P <- Pids],
        Results = [receive {won, P, R} -> R after 10000 -> timeout end || P <- Pids],
        length([R || {ok, 1, _, _} = R <- Results])
    end,
    %% Cold: exactly one session gets the lease.
    ?assertEqual(1, Race()),
    %% Live lease: nobody.
    ?assertEqual(0, Race()),
    %% Abandoned lease (a pod died mid-fetch): taken over by exactly one.
    {ok, 1} = pq_p("UPDATE rdap_cache SET retry_at = now() - interval '1 second' "
                   "WHERE domain = $1", [?BASE]),
    ?assertEqual(1, Race()),
    %% Transient and due: one. Final: never, even with retry_at in the past.
    {ok, 1} = pq_p("UPDATE rdap_cache SET status = 'transient', attempts = 3, "
                   "retry_at = now() - interval '1 second' WHERE domain = $1", [?BASE]),
    ?assertEqual(1, Race()),
    %% The takeover preserved attempts: backoff must keep growing.
    ?assertMatch({ok, _, [{3}]}, pq_p("SELECT attempts FROM rdap_cache WHERE domain = $1",
                                      [?BASE])),
    [begin
         {ok, 1} = pq_p("UPDATE rdap_cache SET status = $2, "
                        "retry_at = now() - interval '1 second' WHERE domain = $1",
                        [?BASE, S]),
         ?assertEqual(0, Race())
     end || S <- [<<"ok">>, <<"not_found">>, <<"unsupported">>]],
    [ok = epgsql:close(C) || C <- Conns],
    ok.

%% ── B: failure classes ───────────────────────────────────────

%% A 503 is not a fact about the domain. It must be retried, later, with a
%% growing gap — and the eventual success must score.
transient_failure_is_retried_with_backoff(_Config) ->
    set_lookup(fun(_) -> {transient, {http, 503}, undefined} end),
    Empty = bifrost_api_handler:rdap_cached(?BASE),
    ?assertEqual(undefined, maps:get(age_days, Empty)),
    ?assertEqual(1, length(calls())),
    ?assertEqual({<<"transient">>, 1}, status_attempts(?BASE)),
    assert_retry_in(?BASE, 3600),
    %% Not due yet: served from the row, no request.
    _ = bifrost_api_handler:rdap_cached(?BASE),
    ?assertEqual(1, length(calls())),
    %% Due, fails again: the gap doubles.
    make_due(?BASE),
    _ = bifrost_api_handler:rdap_cached(?BASE),
    ?assertEqual(2, length(calls())),
    ?assertEqual({<<"transient">>, 2}, status_attempts(?BASE)),
    assert_retry_in(?BASE, 7200),
    %% Due, registry recovers: scored on age at last, and the counter resets.
    make_due(?BASE),
    set_lookup(fun(_) -> registered(12) end),
    Ok = bifrost_api_handler:rdap_cached(?BASE),
    ?assertEqual(3, length(calls())),
    ?assertEqual(12, maps:get(age_days, Ok)),
    ?assertEqual(3, bifrost_api_handler:score_rdap(Ok)),
    ?assertEqual({<<"ok">>, 0}, status_attempts(?BASE)).

%% A registry that says "come back in a day" gets a day, not our 1h default.
retry_after_is_honoured(_Config) ->
    set_lookup(fun(_) -> {transient, rate_limited, 86400} end),
    _ = bifrost_api_handler:rdap_cached(?BASE),
    assert_retry_in(?BASE, 86400).

%% 404 and "no registry for this TLD" are facts: never asked again, even if
%% retry_at somehow ends up in the past.
permanent_failure_is_final(_Config) ->
    [begin
         {ok, _} = pq("DELETE FROM rdap_cache"),
         ets:delete_all_objects(?CALLS),
         set_lookup(fun(_) -> {final, Reason} end),
         R = bifrost_api_handler:rdap_cached(?BASE),
         ?assertEqual(unavailable, maps:get(lookup, R)),
         ?assertEqual({atom_to_binary(Reason), 0}, status_attempts(?BASE)),
         {ok, 1} = pq_p("UPDATE rdap_cache SET retry_at = now() - interval '1 day' "
                        "WHERE domain = $1", [?BASE]),
         _ = bifrost_api_handler:rdap_cached(?BASE),
         [_] = bifrost_api_handler:enrich_with_rdap(
                 [#{domain => ?BASE, score => 1, hits => 1, reasons => []}]),
         timer:sleep(100),
         ?assertEqual(1, length(calls()))
     end || Reason <- [not_found, unsupported]],
    %% And the REAL lookup classifies an unsupported TLD as final, offline.
    ?assertEqual({final, unsupported}, bifrost_api_handler:rdap_lookup(?BASE)).

%% ── C: age ───────────────────────────────────────────────────

%% Looked up 395 days ago when it was 5 days old. The stale age_days column says
%% "5 days, brand new"; the truth is 400 days, which earns nothing. Reading the
%% stored age instead of the registration date fails here.
age_is_computed_at_read(_Config) ->
    {ok, 1} = pq_p("INSERT INTO rdap_cache (domain, status, registered_on, age_days, "
                   "has_transfer_lock, pending_delete, privacy_protected, looked_up) "
                   "VALUES ($1, 'ok', current_date - 400, 5, true, false, false, "
                   "now() - interval '395 days')", [?BASE]),
    R = bifrost_api_handler:rdap_cached(?BASE),
    ?assertEqual(400, maps:get(age_days, R)),
    ?assertEqual(0, bifrost_api_handler:score_rdap(R)),
    ?assertEqual([], bifrost_api_handler:rdap_reasons(R)),
    ?assertEqual([], calls()).

%% ── D: keying, scoring, pool ─────────────────────────────────

%% One registration, many throwaway subdomains. All of them must land on the base
%% domain's single entry.
subdomain_variants_share_one_entry(_Config) ->
    seed(?BASE, 7, false, false, false),
    Expected = #{age_days => 7, has_transfer_lock => false,
                 pending_delete => false, privacy_protected => false, lookup => done},
    [?assertEqual(Expected, bifrost_api_handler:rdap_cached(V))
     || V <- [?BASE,
              <<"ads.", (?BASE)/binary>>,
              <<"1.ads.", (?BASE)/binary>>,
              <<"2.ads.", (?BASE)/binary>>]],
    ?assertEqual({ok, [{?BASE}]}, all_domains()),
    ?assertEqual([], calls()).

%% Pure functions, no DB. Provenance is carried by the tag name itself, and
%% only DISCRIMINATING fields earn score — see score_rdap/1 for the argument.
rdap_signals_are_namespaced_and_scoring_is_total(_Config) ->
    Full = #{age_days => 10, has_transfer_lock => false,
             pending_delete => true, privacy_protected => true},
    Tags = bifrost_api_handler:rdap_reasons(Full),
    ?assertEqual(4, length(Tags)),
    [?assertMatch(<<"rdap:", _/binary>>, T) || T <- Tags],

    ?assertEqual(3, bifrost_api_handler:score_rdap(#{age_days => 10})),
    ?assertEqual(2, bifrost_api_handler:score_rdap(#{age_days => 100})),
    ?assertEqual(1, bifrost_api_handler:score_rdap(#{age_days => 300})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{age_days => 400})),
    ?assertEqual(-3, bifrost_api_handler:score_rdap(#{age_days => 4000})),
    ?assertEqual(3, bifrost_api_handler:score_rdap(#{pending_delete => true})),

    ?assertEqual(0, bifrost_api_handler:score_rdap(#{privacy_protected => true})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{has_transfer_lock => false})),
    ?assertEqual([<<"rdap:privacy_protected">>],
                 bifrost_api_handler:rdap_reasons(#{privacy_protected => true})),
    ?assertEqual([<<"rdap:no_transfer_lock">>],
                 bifrost_api_handler:rdap_reasons(#{has_transfer_lock => false})),

    %% An absent field is "no signal", never a crash — including the
    %% pending/unavailable shapes the cache now returns.
    ?assertEqual([], bifrost_api_handler:rdap_reasons(#{})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{})),
    [begin
         Empty = #{age_days => undefined, has_transfer_lock => undefined,
                   pending_delete => undefined, privacy_protected => undefined,
                   lookup => L},
         ?assertEqual([], bifrost_api_handler:rdap_reasons(Empty)),
         ?assertEqual(0, bifrost_api_handler:score_rdap(Empty))
     end || L <- [pending, unavailable]],
    ?assertEqual([], bifrost_api_handler:rdap_reasons(
                       #{age_days => 400, has_transfer_lock => true,
                         pending_delete => false, privacy_protected => false})).

%% A caller binding the wrong type must cost that ONE request, not the pool.
%%
%% Found live: GET /api/clients/:ip/suspicious passed the IP as a binary to an
%% inet parameter. epgsql encodes parameters inside its socket process, so the
%% function_clause killed the socket and exited the gen_server:call bifrost_db_pool
%% was blocked in — so every "scan" click restarted the pool and broke whatever
%% query_writer or blocklist_manager had in flight. trap_exit cannot help: the
%% exit arrives as the result of our own call, not as a signal.
bad_parameter_type_does_not_kill_the_pool(_Config) ->
    Pid = whereis(bifrost_db_pool),
    ?assert(is_pid(Pid)),
    ?assertMatch({error, _},
                 pq_p("SELECT $1::inet", [<<"172.18.0.1">>])),
    ?assertEqual(Pid, whereis(bifrost_db_pool)),
    ?assert(is_process_alive(Pid)),
    ok = wait_connected(50),
    ?assertMatch({ok, _, [{<<"1">>}]}, pq("SELECT 1")),
    ?assertMatch({ok, _, [{{172,18,0,1}}]},
                 pq_p("SELECT $1::inet", [{172,18,0,1}])).

%% -- Fake registry ---------------------------------------------

fake_lookup(Base) ->
    ets:insert(?CALLS, {self(), Base}),
    (persistent_term:get({?MODULE, lookup}))(Base).

set_lookup(F) -> persistent_term:put({?MODULE, lookup}, F).

calls() -> ets:tab2list(?CALLS).

%% A successful lookup for a domain registered N days ago (UTC, like Postgres).
registered(Days) ->
    {Today, _} = calendar:universal_time(),
    {Y, M, D} = calendar:gregorian_days_to_date(
                  calendar:date_to_gregorian_days(Today) - Days),
    Date = iolist_to_binary(io_lib:format("~4..0B-~2..0B-~2..0BT00:00:00Z", [Y, M, D])),
    {ok, #{registration_date => Date, has_transfer_lock => true,
           pending_delete => false, privacy_protected => false}}.

%% -- Helpers ---------------------------------------------------

seed(Domain, Age, Lock, Del, Priv) ->
    {ok, 1} = pq_p("INSERT INTO rdap_cache (domain, status, registered_on, has_transfer_lock, "
                   "pending_delete, privacy_protected) "
                   "VALUES ($1, 'ok', current_date - $2::int, $3, $4, $5)",
                   [Domain, Age, Lock, Del, Priv]),
    ok.

status_attempts(Domain) ->
    {ok, _, [{S, A}]} = pq_p("SELECT status, attempts FROM rdap_cache WHERE domain = $1",
                             [Domain]),
    {S, A}.

%% retry_at is Secs from now, give or take test runtime.
assert_retry_in(Domain, Secs) ->
    {ok, _, [{Delta}]} = pq_p("SELECT EXTRACT(EPOCH FROM retry_at - now())::int "
                              "FROM rdap_cache WHERE domain = $1", [Domain]),
    ?assert(Delta > Secs - 30 andalso Delta =< Secs, {retry_in, Delta, expected, Secs}).

make_due(Domain) ->
    {ok, 1} = pq_p("UPDATE rdap_cache SET retry_at = now() - interval '1 second' "
                   "WHERE domain = $1", [Domain]),
    ok.

wait_status(Domain, Want) -> wait_status(Domain, Want, 100).
wait_status(_Domain, Want, 0) -> {error, {never_reached, Want}};
wait_status(Domain, Want, N) ->
    case pq_p("SELECT status FROM rdap_cache WHERE domain = $1", [Domain]) of
        {ok, _, [{Want}]} -> ok;
        _ -> timer:sleep(50), wait_status(Domain, Want, N - 1)
    end.

wait_idle(0) -> {error, rdap_not_idle};
wait_idle(N) ->
    case bifrost_rdap:status() of
        #{queued := 0, in_flight := 0} -> ok;
        _ -> timer:sleep(50), wait_idle(N - 1)
    end.

row_count(Domain) ->
    {ok, _, [{N}]} = pq_p("SELECT count(*) FROM rdap_cache WHERE domain = $1", [Domain]),
    N.

all_domains() ->
    {ok, _, Rows} = pq("SELECT domain FROM rdap_cache ORDER BY domain"),
    {ok, Rows}.

pq(Sql) -> bifrost_db_pool:query(Sql).
pq_p(Sql, Params) -> bifrost_db_pool:equery(Sql, Params).

wait_connected(0) -> {error, timeout};
wait_connected(N) ->
    case pq("SELECT 1") of
        {ok, _, _} -> ok;
        _ -> timer:sleep(200), wait_connected(N - 1)
    end.

raw_connect(#{host := H, port := P, user := U, pass := Pw, name := N}) ->
    {ok, C} = epgsql:connect(#{host => H, port => P, username => U,
                               password => Pw, database => N}),
    C.

sq(Conn, Sql) ->
    case epgsql:squery(Conn, Sql) of
        {error, E} -> ct:fail({sql_failed, Sql, E});
        R -> R
    end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

getenv(Var, Default) ->
    case os:getenv(Var) of
        false -> Default;
        "" -> Default;
        V -> V
    end.

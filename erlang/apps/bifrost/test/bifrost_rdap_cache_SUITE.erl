%% Common Test suite for the RDAP read-through cache
%% (bifrost_api_handler:rdap_cached/1), against a REAL Postgres.
%%
%% The bug this suite exists to prevent: enrich_with_rdap/1 called rdap_lookup/1
%% directly, so `rdap_cache` was written by bifrost_domain_analyzer and read by
%% nobody on the page-load path. Ticking "RDAP enrich" on the Clients page issued
%% up to 10 sequential live registry requests (3s connect + 5s read each) and
%% re-issued all of them on every refresh, against registries that rate-limit.
%%
%%  1. cache_hit_never_reaches_the_registry — the core claim. Seeds a row whose
%%     values a live lookup could not produce, then asserts they come back. If the
%%     SELECT is dropped, the fetch path returns all-undefined and this fails.
%%  2. failed_lookup_is_cached_so_it_is_not_retried — most TLDs have no
%%     rdap_server/1 entry, and a 404 or timeout repeats just as reliably as a
%%     hit. Storing only successes means those domains are re-requested on every
%%     scan AND every page load, which is the expensive half of the original bug.
%%     Asserts a negative row is written, survives, and is not duplicated.
%%  3. subdomain_variants_share_one_entry — RDAP describes the registrable
%%     domain, and these candidates are throwaway numbered subdomains
%%     (1.ads.x.com, 2.ads.x.com, ...). Keying on the queried name instead of the
%%     base would issue one registry request per variant for one registration and
%%     never hit the analyzer's entry for the same site.
%%  4. rdap_signals_are_namespaced_and_scoring_is_total — the tags carry their own
%%     provenance (`rdap:` prefix) so both UIs colour them without a shared
%%     catalogue of tag names. Renaming one without the prefix silently turns it
%%     grey. Scoring must also survive an absent field: a cached negative entry
%%     and a partial registry response both yield `undefined`, and the previous
%%     maps:get/2 with no default would crash the scan on either.
%%
%% NO NETWORK: every domain here uses an unsupported TLD, so rdap_server/1
%% returns undefined and the fetch path is a pure function. The suite is
%% deterministic and cannot be broken by a registry being slow or down.
%%
%% Connection is taken from env, as in bifrost_retention_SUITE:
%%   BIFROST_TEST_DB_HOST (default "postgres"), BIFROST_TEST_DB_PORT (5432),
%%   BIFROST_TEST_DB_NAME (bifrost), BIFROST_TEST_DB_USER (bifrost),
%%   BIFROST_TEST_DB_PASSWORD (bifrost).
%%
%% ISOLATION: a throwaway DATABASE, not a schema. The pool runs the real
%% migrations into it on connect, so `rdap_cache` here is the production schema
%% including migration 010 — and the live dev cache is in another database, out of
%% reach of the DELETE in init_per_testcase.
-module(bifrost_rdap_cache_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([cache_hit_never_reaches_the_registry/1,
         enrich_path_uses_the_cache_not_a_live_lookup/1,
         failed_lookup_is_cached_so_it_is_not_retried/1,
         subdomain_variants_share_one_entry/1,
         rdap_signals_are_namespaced_and_scoring_is_total/1,
         bad_parameter_type_does_not_kill_the_pool/1]).

%% rdap_server/1 has no entry for this, so no request is ever made.
-define(BASE, <<"nosuchregistry.invalidtld">>).


all() ->
    [cache_hit_never_reaches_the_registry,
     enrich_path_uses_the_cache_not_a_live_lookup,
     failed_lookup_is_cached_so_it_is_not_retried,
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

    %% start_link links to THIS process, which exits before the testcases run.
    {ok, CfgPid} = bifrost_config_server:start_link(),
    erlang:unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    erlang:unlink(PoolPid),
    ok = wait_connected(50),
    %% Migration 010 must have landed, or every test below is asserting on a
    %% schema that does not exist in production.
    {ok, _, Cols} = pq("SELECT column_name FROM information_schema.columns "
                       "WHERE table_name = 'rdap_cache'"),
    Names = [C || {C} <- Cols],
    [?assert(lists:member(N, Names)) || N <- [<<"has_transfer_lock">>,
                                              <<"pending_delete">>,
                                              <<"privacy_protected">>]],
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    Admin = raw_connect(?config(db, Config)),
    sq(Admin, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)"),
    ok = epgsql:close(Admin),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

init_per_testcase(_Case, Config) ->
    {ok, _} = pq("DELETE FROM rdap_cache"),
    Config.

%% A live lookup for an unsupported TLD yields all-undefined, so these values can
%% ONLY have come from the row. Deleting the cache read fails here.
cache_hit_never_reaches_the_registry(_Config) ->
    seed(?BASE, 42, false, true, true),
    ?assertEqual(#{age_days => 42,
                   has_transfer_lock => false,
                   pending_delete => true,
                   privacy_protected => true},
                 bifrost_api_handler:rdap_cached(?BASE)),
    %% A hit must not rewrite the row, and must not add another.
    ?assertEqual(1, row_count(?BASE)),
    %% The signals must survive the round trip into the scorer, not just the map.
    ?assertEqual([<<"rdap:new_domain">>, <<"rdap:no_transfer_lock">>,
                  <<"rdap:pending_delete">>, <<"rdap:privacy_protected">>],
                 bifrost_api_handler:rdap_reasons(bifrost_api_handler:rdap_cached(?BASE))).

%% THE regression test for the reported bug. The tests above prove rdap_cached/1
%% works; this one proves the code path the Clients page actually calls goes
%% THROUGH it. enrich_with_rdap/1 used to call rdap_lookup/1 directly, so a cache
%% that worked perfectly was simply never consulted on page load.
%%
%% The seeded values cannot come from a live lookup (unsupported TLD yields
%% nothing), so if this path stops reading the cache the score and the rdap map
%% both collapse and this fails.
enrich_path_uses_the_cache_not_a_live_lookup(_Config) ->
    seed(?BASE, 12, false, true, true),
    Candidate = #{domain => ?BASE, score => 1, hits => 5, reasons => [<<"entropy">>]},
    [Enriched] = bifrost_api_handler:enrich_with_rdap([Candidate]),
    %% age 12d (+3) and pending_delete (+3). The two non-discriminating flags are
    %% seeded true/false here precisely to assert they add nothing.
    ?assertEqual(1 + 6, maps:get(score, Enriched)),
    ?assertEqual(#{age_days => 12, has_transfer_lock => false,
                   pending_delete => true, privacy_protected => true},
                 maps:get(rdap, Enriched)),
    %% Pre-existing reasons are kept, registry tags appended and namespaced.
    Reasons = maps:get(reasons, Enriched),
    ?assert(lists:member(<<"entropy">>, Reasons)),
    ?assert(lists:member(<<"rdap:new_domain">>, Reasons)),
    ?assert(lists:member(<<"rdap:privacy_protected">>, Reasons)),
    %% A hit must not rewrite the row, and must not add a second one.
    ?assertEqual(1, row_count(?BASE)),
    ?assertEqual({ok, [{?BASE}]}, all_domains()).

%% An unsupported TLD, a 404 and a timeout are all repeatable. The negative entry
%% is what stops them being re-requested on every scan and page load.
failed_lookup_is_cached_so_it_is_not_retried(_Config) ->
    ?assertEqual(0, row_count(?BASE)),
    Empty = #{age_days => undefined, has_transfer_lock => undefined,
              pending_delete => undefined, privacy_protected => undefined},
    ?assertEqual(Empty, bifrost_api_handler:rdap_cached(?BASE)),
    %% The failure itself is now cached: a row exists, all columns NULL.
    ?assertEqual(1, row_count(?BASE)),
    ?assertMatch({ok, _, [{null, null, null, null}]},
                 pq_p("SELECT age_days, has_transfer_lock, pending_delete, "
                      "privacy_protected FROM rdap_cache WHERE domain = $1", [?BASE])),
    %% Second call is served from that row, and does not duplicate it.
    ?assertEqual(Empty, bifrost_api_handler:rdap_cached(?BASE)),
    ?assertEqual(1, row_count(?BASE)).

%% One registration, many throwaway subdomains. All of them must land on the base
%% domain's single entry — both to avoid N requests for one registration, and so
%% the analyzer and the per-client scan share what the other already fetched.
subdomain_variants_share_one_entry(_Config) ->
    seed(?BASE, 7, false, false, false),
    Expected = #{age_days => 7, has_transfer_lock => false,
                 pending_delete => false, privacy_protected => false},
    [?assertEqual(Expected, bifrost_api_handler:rdap_cached(V))
     || V <- [?BASE,
              <<"ads.", (?BASE)/binary>>,
              <<"1.ads.", (?BASE)/binary>>,
              <<"2.ads.", (?BASE)/binary>>]],
    %% Still exactly one row, and no row under any variant name.
    ?assertEqual({ok, [{?BASE}]}, all_domains()).

%% Pure functions, no DB. Provenance is carried by the tag name itself, which is
%% what lets both templates colour registry signals without a shared list. And
%% only DISCRIMINATING fields earn score — see score_rdap/1 for the argument.
rdap_signals_are_namespaced_and_scoring_is_total(_Config) ->
    Full = #{age_days => 10, has_transfer_lock => false,
             pending_delete => true, privacy_protected => true},
    Tags = bifrost_api_handler:rdap_reasons(Full),
    ?assertEqual(4, length(Tags)),
    [?assertMatch(<<"rdap:", _/binary>>, T) || T <- Tags],

    %% Scored: young registration (graduated) and pending delete.
    ?assertEqual(3, bifrost_api_handler:score_rdap(#{age_days => 10})),
    ?assertEqual(2, bifrost_api_handler:score_rdap(#{age_days => 100})),
    ?assertEqual(1, bifrost_api_handler:score_rdap(#{age_days => 300})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{age_days => 4000})),
    ?assertEqual(3, bifrost_api_handler:score_rdap(#{pending_delete => true})),

    %% NOT scored: near-universal post-GDPR redaction, and a missing transfer lock
    %% (absent by ICANN rule for 60 days, so it restates "recently registered").
    %% Scoring these adds a constant offset to most of the internet, which only
    %% moves the threshold. They stay visible as tags.
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{privacy_protected => true})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{has_transfer_lock => false})),
    ?assertEqual([<<"rdap:privacy_protected">>],
                 bifrost_api_handler:rdap_reasons(#{privacy_protected => true})),
    ?assertEqual([<<"rdap:no_transfer_lock">>],
                 bifrost_api_handler:rdap_reasons(#{has_transfer_lock => false})),

    %% An absent field is "no signal", never a crash: a cached negative entry and
    %% a registry that omits a section both arrive here as undefined.
    ?assertEqual([], bifrost_api_handler:rdap_reasons(#{})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{})),
    ?assertEqual([], bifrost_api_handler:rdap_reasons(
                       #{age_days => undefined, has_transfer_lock => undefined,
                         pending_delete => undefined, privacy_protected => undefined})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(
                      #{age_days => undefined, pending_delete => undefined})),
    %% A locked, established, non-private domain produces no tags at all.
    ?assertEqual([], bifrost_api_handler:rdap_reasons(
                       #{age_days => 4000, has_transfer_lock => true,
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
    %% A binary bound to inet: exactly the shape of the original bug.
    ?assertMatch({error, _},
                 pq_p("SELECT $1::inet", [<<"172.18.0.1">>])),
    %% Same process, still serving. Reconnect is async, so allow for it.
    ?assertEqual(Pid, whereis(bifrost_db_pool)),
    ?assert(is_process_alive(Pid)),
    ok = wait_connected(50),
    ?assertMatch({ok, _, [{<<"1">>}]}, pq("SELECT 1")),
    %% And a correctly-typed inet parameter still works.
    ?assertMatch({ok, _, [{{172,18,0,1}}]},
                 pq_p("SELECT $1::inet", [{172,18,0,1}])).

%% -- Helpers ---------------------------------------------------

seed(Domain, Age, Lock, Del, Priv) ->
    {ok, 1} = pq_p("INSERT INTO rdap_cache (domain, age_days, has_transfer_lock, "
                   "pending_delete, privacy_protected) VALUES ($1, $2, $3, $4, $5)",
                   [Domain, Age, Lock, Del, Priv]),
    ok.

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

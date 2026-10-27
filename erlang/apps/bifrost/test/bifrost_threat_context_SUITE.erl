%% Contextual threat signals (bifrost_threat_context) against a REAL Postgres
%% scratch database and single-node Mnesia holding the blocklist cache, and the
%% analyzer's production ranking path (find_candidates/0) on top of them.
-module(bifrost_threat_context_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([cname_into_an_enabled_blocklist_is_flagged/1,
         blocked_sibling_comes_from_manual_and_threat_blocks/1,
         widespread_needs_the_client_threshold/1,
         newly_seen_needs_history/1,
         ranking_admits_cloaked_trackers_and_rejects_shared_infrastructure/1]).

-define(H, 24).

all() ->
    [cname_into_an_enabled_blocklist_is_flagged,
     blocked_sibling_comes_from_manual_and_threat_blocks,
     widespread_needs_the_client_threshold,
     newly_seen_needs_history,
     ranking_admits_cloaked_trackers_and_rejects_shared_infrastructure].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(epgsql),
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_context_" ++ integer_to_list(erlang:system_time(millisecond)),
    Admin = raw_connect(Db, maps:get(name, Db)),
    {ok, _, _} = epgsql:squery(Admin, "CREATE DATABASE " ++ Scratch),
    ok = epgsql:close(Admin),

    CfgPath = filename:join(?config(priv_dir, Config), "context_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n"
        "{upstreams, [[{address, \"192.0.2.53\"}, {port, 53}]]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    os:unsetenv("BIFROST_CLUSTER_NODES"),
    os:unsetenv("BIFROST_CLUSTER_SERVICE"),
    application:set_env(mnesia, dir, filename:join(?config(priv_dir, Config), "mnesia")),
    ok = bifrost_mnesia:init_tables(),

    {ok, CfgPid} = bifrost_config_server:start_link(),
    unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    unlink(PoolPid),
    ok = wait_connected(50),
    C = [{db, Db}, {scratch, Scratch} | Config],
    sql(C, "CREATE TABLE IF NOT EXISTS query_log_context_test PARTITION OF query_log DEFAULT"),
    %% One enabled list with a same-list exception, and one DISABLED list that
    %% is still cached: it must never count.
    sql(C, "INSERT INTO blocklists (name, url, enabled, source) VALUES "
           "('ct-on', 'https://example.invalid/on', true, 'ui'), "
           "('ct-off', 'https://example.invalid/off', false, 'ui')"),
    ok = bifrost_mnesia:write_cache("ct-on", [<<"tracker.net">>, <<"@@safe.tracker.net">>,
                                              <<"other.org">>], undefined),
    ok = bifrost_mnesia:write_cache("ct-off", [<<"disabled.net">>], undefined),
    C.

end_per_suite(Config) ->
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    mnesia:stop(),
    Admin = raw_connect(?config(db, Config), maps:get(name, ?config(db, Config))),
    epgsql:squery(Admin, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)"),
    epgsql:close(Admin),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

init_per_testcase(_TC, Config) ->
    [sql(Config, "DELETE FROM " ++ T)
     || T <- ["query_log", "manual_blocks", "allowlist", "suspicious_candidates", "rdap_cache"]],
    Config.

%% ── cases ─────────────────────────────────────────────────────

%% Rust's semantics, from the stored answers: blocked when an enabled list or a
%% manual block covers any suffix of the CNAME target, unless the SAME list has
%% a @@ exception for it, or the allowlist covers it.
cname_into_an_enabled_blocklist_is_flagged(Config) ->
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('manualblocked.org')"),
    sql(Config, "INSERT INTO allowlist (domain) VALUES ('x.tracker.net')"),
    Cases = [{"metrics.shop.com", "C1.Tracker.NET."},
             {"safe.shop.com", "a.safe.tracker.net."},
             {"allowed.shop.com", "deep.x.tracker.net."},
             {"manual.shop.com", "m.manualblocked.org."},
             {"off.shop.com", "z.disabled.net."},
             {"clean.shop.com", "edge.cdn.example."}],
    [log(Config, "10.0.0.1", D, cname(T)) || {D, T} <- Cases],
    Ctx = bifrost_threat_context:signals([list_to_binary(D) || {D, _} <- Cases], ?H),
    Reasons = fun(D) -> maps:get(reasons, maps:get(D, Ctx)) end,
    ?assert(lists:member(<<"cname_to_blocked:c1.tracker.net">>, Reasons(<<"metrics.shop.com">>))),
    ?assertEqual(6, maps:get(score, maps:get(<<"metrics.shop.com">>, Ctx))),
    ?assert(lists:member(<<"cname_to_blocked:m.manualblocked.org">>, Reasons(<<"manual.shop.com">>))),
    [?assertEqual([], [R || <<"cname_to_blocked:", _/binary>> = R <- Reasons(D)], D)
     || D <- [<<"safe.shop.com">>, <<"allowed.shop.com">>, <<"off.shop.com">>,
              <<"clean.shop.com">>]].

blocked_sibling_comes_from_manual_and_threat_blocks(Config) ->
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('1.sib.example.com')"),
    sql(Config, "INSERT INTO suspicious_candidates (domain, score, status) VALUES "
                "('1.cand.example.com', 5, 'blocked'), ('1.dis.example.com', 5, 'dismissed')"),
    Ds = [<<"2.sib.example.com">>, <<"2.cand.example.com">>, <<"2.dis.example.com">>,
          <<"2.alone.example.com">>],
    Ctx = bifrost_threat_context:signals(Ds, ?H),
    Has = fun(D) -> lists:member(<<"blocked_sibling">>, maps:get(reasons, maps:get(D, Ctx))) end,
    ?assert(Has(<<"2.sib.example.com">>)),
    ?assert(Has(<<"2.cand.example.com">>)),
    ?assertNot(Has(<<"2.dis.example.com">>)),
    ?assertNot(Has(<<"2.alone.example.com">>)).

%% 10 active clients: the floor of 5 applies (25% would be 3).
widespread_needs_the_client_threshold(Config) ->
    [log(Config, ip(N), "busy.example.com") || N <- lists:seq(1, 5)],
    [log(Config, ip(N), "quiet.example.com") || N <- lists:seq(1, 4)],
    [log(Config, ip(N), "filler.example.com") || N <- lists:seq(6, 10)],
    log(Config, ip(1), "solo.example.com"),
    Ctx = bifrost_threat_context:signals(
            [<<"busy.example.com">>, <<"quiet.example.com">>, <<"solo.example.com">>], ?H),
    ?assertMatch(#{score := -2, reasons := [<<"widespread">>], clients := 5},
                 maps:get(<<"busy.example.com">>, Ctx)),
    ?assertMatch(#{score := 0, reasons := [], clients := 4},
                 maps:get(<<"quiet.example.com">>, Ctx)),
    ?assertMatch(#{score := 0, reasons := [<<"single_client">>]},
                 maps:get(<<"solo.example.com">>, Ctx)).

newly_seen_needs_history(Config) ->
    log(Config, ip(1), "new.example.com"),
    log(Config, ip(1), "old.example.com"),
    New = fun() ->
        Ctx = bifrost_threat_context:signals([<<"new.example.com">>, <<"old.example.com">>], ?H),
        [D || {D, #{reasons := R}} <- maps:to_list(Ctx), lists:member(<<"newly_seen">>, R)]
    end,
    %% Only today's traffic: every domain would look new, so nothing is.
    ?assertEqual([], New()),
    log(Config, ip(1), "old.example.com", null, "now() - interval '40 days'"),
    ?assertEqual([<<"new.example.com">>], New()).

%% End to end through the analyzer's production ranking. A tracker behind a
%% first-party name has no lexical signal at all and must still be found; a
%% lexically suspicious host that most devices use must not be.
ranking_admits_cloaked_trackers_and_rejects_shared_infrastructure(Config) ->
    [log(Config, ip(N), "filler.example.com") || N <- lists:seq(1, 10)],
    [log(Config, ip(N), "metrics.shop.com", cname("c1.tracker.net.")) || N <- [1, 2]],
    [log(Config, ip(N), "3.pool.ntp.org") || N <- lists:seq(1, 8)],
    [log(Config, ip(N), "4.cdn-sync.example.org") || N <- lists:seq(1, 8)],
    log(Config, ip(1), "5.cdn-sync.example.net"),
    Found = maps:from_list([{maps:get(domain, C), C}
                            || C <- bifrost_domain_analyzer:find_candidates()]),
    ?assertMatch(#{reasons := [<<"cname_to_blocked:c1.tracker.net">>]},
                 maps:get(<<"metrics.shop.com">>, Found)),
    ?assert(maps:is_key(<<"5.cdn-sync.example.net">>, Found)),
    ?assertNot(maps:is_key(<<"3.pool.ntp.org">>, Found)),
    ?assertNot(maps:is_key(<<"4.cdn-sync.example.org">>, Found)),
    ?assertNot(maps:is_key(<<"filler.example.com">>, Found)).

%% ── helpers ───────────────────────────────────────────────────

ip(N) -> "10.0.0." ++ integer_to_list(N).

cname(Target) ->
    "[{\"rtype\": \"CNAME\", \"value\": \"" ++ Target ++ "\"}, "
    "{\"rtype\": \"A\", \"value\": \"192.0.2.1\"}]".

log(Config, Ip, Domain) -> log(Config, Ip, Domain, null).
log(Config, Ip, Domain, Records) -> log(Config, Ip, Domain, Records, "now()").
log(Config, Ip, Domain, Records, At) ->
    Rec = case Records of null -> "NULL"; _ -> "'" ++ Records ++ "'::jsonb" end,
    sql(Config, "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode, "
                "response_records, queried_at) VALUES ('" ++ Ip ++ "', '" ++ Domain ++
                "', 1, 'NOERROR', 'NOERROR', " ++ Rec ++ ", " ++ At ++ ")").

with_direct(Config, Fun) ->
    C = raw_connect(?config(db, Config), ?config(scratch, Config)),
    try Fun(C) after epgsql:close(C) end.

sql(Config, Sql) ->
    case with_direct(Config, fun(C) -> epgsql:squery(C, Sql) end) of
        {ok, _} -> ok;
        {ok, _, _} -> ok;
        Err -> ct:fail({sql_failed, Sql, Err})
    end.

raw_connect(Db, Name) ->
    {ok, C} = epgsql:connect(maps:get(host, Db), maps:get(user, Db), maps:get(pass, Db),
                             [{port, maps:get(port, Db)}, {database, Name}]),
    C.

wait_connected(0) -> {error, db_never_connected};
wait_connected(N) ->
    case catch bifrost_db_pool:query("SELECT 1 FROM manual_blocks LIMIT 1") of
        {ok, _, _} -> ok;
        _ -> timer:sleep(200), wait_connected(N - 1)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

%% Rule endpoints (blocks, unblock, allowlist, threats, client blocks, rewrites)
%% over REAL HTTP through the production router + handler, against a REAL
%% Postgres scratch database and single-node Mnesia.
%%
%% The invariant under test: a domain is never BOTH manually blocked and
%% allowlisted, in any spelling. The query log reports names as queried, so an
%% "Unblock" click can carry `Ads.Example.COM.` for a block stored as
%% `ads.example.com`; and the block/allow pair must change in one statement, or a
%% failure halfway leaves the operator with neither (or both).
-module(bifrost_rules_api_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([unblock_normalizes_and_clears_the_stored_block/1,
         unblock_is_atomic/1,
         block_normalizes_and_clears_an_allow/1,
         threat_block_normalizes_and_clears_an_allow/1,
         delete_endpoints_normalize/1,
         client_block_normalizes/1,
         rewrite_domain_is_normalized/1,
         invalid_domains_are_rejected/1,
         trends_have_rfc3339_timestamps/1,
         settings_compare_and_swap/1,
         settings_api_is_safe_and_revisioned/1,
         client_blocks_are_listed/1,
         clients_report_last_seen/1,
         query_log_and_clients_share_the_dashboard_window/1]).

-define(PORT, 18123).

all() ->
    [unblock_normalizes_and_clears_the_stored_block,
     unblock_is_atomic,
     block_normalizes_and_clears_an_allow,
     threat_block_normalizes_and_clears_an_allow,
     delete_endpoints_normalize,
     client_block_normalizes,
     rewrite_domain_is_normalized,
     invalid_domains_are_rejected,
     trends_have_rfc3339_timestamps,
     settings_compare_and_swap,
     settings_api_is_safe_and_revisioned,
     client_blocks_are_listed,
     clients_report_last_seen,
     query_log_and_clients_share_the_dashboard_window].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(epgsql),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(inets),
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_rules_" ++ integer_to_list(erlang:system_time(millisecond)),
    Admin = raw_connect(Db, maps:get(name, Db)),
    {ok, _, _} = epgsql:squery(Admin, "CREATE DATABASE " ++ Scratch),
    ok = epgsql:close(Admin),

    CfgPath = filename:join(?config(priv_dir, Config), "rules_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n"
        "{upstreams, [[{address, \"192.0.2.53\"}, {port, 53}]]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    os:unsetenv("BIFROST_CLUSTER_NODES"),
    os:unsetenv("BIFROST_CLUSTER_SERVICE"),
    MnesiaDir = filename:join(?config(priv_dir, Config), "mnesia"),
    application:set_env(mnesia, dir, MnesiaDir),
    ok = bifrost_mnesia:init_tables(),

    {ok, CfgPid} = bifrost_config_server:start_link(),
    unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    unlink(PoolPid),
    ok = wait_connected(50),
    {ok, SettingsPid} = bifrost_dns_settings_server:start_link(),
    unlink(SettingsPid),

    Dispatch = cowboy_router:compile(bifrost_router:routes()),
    {ok, _} = cowboy:start_clear(rules_ct_listener, [{port, ?PORT}],
                                 #{env => #{dispatch => Dispatch}}),
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    cowboy:stop_listener(rules_ct_listener),
    stop(bifrost_dns_settings_server),
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
     || T <- ["manual_blocks", "allowlist", "client_blocks", "rewrites", "suspicious_candidates"]],
    Config.

%% ── cases ─────────────────────────────────────────────────────

settings_compare_and_swap(_Config) ->
    {ok, Initial} = bifrost_dns_settings_store:read(),
    Revision = maps:get(revision, Initial),
    {ok, Saved} = bifrost_dns_settings_store:save(Revision,
        #{<<"cache">> => #{<<"min_ttl">> => 0, <<"max_ttl">> => 1200,
                           <<"max_entries">> => 5000}}, 7200, 3),
    ?assertEqual(Revision + 1, maps:get(revision, Saved)),
    ?assertEqual(7200, maps:get(ptr_ttl_seconds, Saved)),
    ?assertEqual(3, maps:get(retention_months, Saved)),
    ?assertEqual({error, conflict}, bifrost_dns_settings_store:save(Revision, #{}, 60, 1)),
    {ok, ReadBack} = bifrost_dns_settings_store:read(),
    ?assertEqual(Saved, ReadBack),
    {ok, Reset} = bifrost_dns_settings_store:save(Revision + 1, #{}, 21600, 6),
    ?assertEqual(#{}, maps:get(overrides, Reset)).

client_blocks_are_listed(_Config) ->
    ?assertEqual(200, post("/api/client-blocks", #{client_ip => <<"192.0.2.7">>,
                                                    domain => <<"Games.Example.">>})),
    {200, #{<<"blocks">> := Blocks}} = json_request(get, "/api/client-blocks", none),
    ?assertEqual([#{<<"client_ip">> => <<"192.0.2.7">>, <<"domain">> => <<"games.example">>}],
                 Blocks).

query_log_and_clients_share_the_dashboard_window(Config) ->
    sql(Config, "CREATE TABLE IF NOT EXISTS query_log_dashboard_test PARTITION OF query_log DEFAULT"),
    sql(Config, "DELETE FROM query_log WHERE client_ip = '198.51.100.7'"),
    sql(Config, "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode, queried_at) VALUES "
                "('198.51.100.7', 'recent.window', 1, 'NOERROR', 'NOERROR', now() - interval '1 hour'), "
                "('198.51.100.7', 'week.window', 1, 'NOERROR', 'NOERROR', now() - interval '3 days'), "
                "('198.51.100.7', 'old.window', 1, 'NOERROR', 'NOERROR', now() - interval '120 days')"),
    Count = fun(Range) ->
        Q = "/api/query-log?search=198.51.100.7" ++ case Range of none -> ""; R -> "&range=" ++ R end,
        {200, #{<<"total">> := T}} = json_request(get, Q, none), T
    end,
    ?assertEqual(2, Count(none)),
    ?assertEqual(2, Count("90d")),
    ?assertEqual(1, Count("24h")),
    ?assertEqual(2, Count("7d")),
    ?assertEqual(3, Count("all")),
    ?assertEqual(2, Count("bogus")),
    {200, #{<<"clients">> := [C]}} = json_request(get, "/api/clients?ip=198.51.100.7", none),
    ?assertEqual(2, maps:get(<<"total">>, C)),
    {200, #{<<"clients">> := All}} = json_request(get, "/api/clients", none),
    [C2] = [X || X <- All, maps:get(<<"ip">>, X) =:= <<"198.51.100.7">>],
    ?assertEqual(2, maps:get(<<"total">>, C2)).

clients_report_last_seen(Config) ->
    sql(Config, "CREATE TABLE IF NOT EXISTS query_log_dashboard_test PARTITION OF query_log DEFAULT"),
    sql(Config, "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode, queried_at) "
                "VALUES ('192.0.2.9', 'seen.example', 1, 'NOERROR', 'NOERROR', date_trunc('second', now()) - interval '2 days')"),
    {200, #{<<"clients">> := [C]}} = json_request(get, "/api/clients?ip=192.0.2.9", none),
    Seen = calendar:rfc3339_to_system_time(binary_to_list(maps:get(<<"last_seen">>, C))),
    Age = erlang:system_time(second) - Seen,
    ?assert(Age >= 2 * 86400 andalso Age < 2 * 86400 + 120).

settings_api_is_safe_and_revisioned(_Config) ->
    {200, Current} = json_request(get, "/api/settings", none),
    Body = jsx:encode(Current),
    ?assertEqual(nomatch, binary:match(Body, [<<"password">>, <<"cookie">>, <<"secret">>])),
    #{<<"revision">> := Revision, <<"settings">> := Settings} = Current,
    Cache = maps:get(<<"cache">>, Settings),
    Changed = Settings#{<<"cache">> => Cache#{<<"max_entries">> => 4321}},
    {200, Saved} = json_request(put, "/api/settings",
        #{revision => Revision, settings => Changed, reset => []}),
    ?assertEqual(Revision + 1, maps:get(<<"revision">>, Saved)),
    ?assertEqual(<<"pending">>, maps:get(<<"state">>, Saved)),
    {409, _} = json_request(put, "/api/settings",
        #{revision => Revision, settings => Changed, reset => []}),
    {400, _} = json_request(put, "/api/settings",
        #{revision => Revision + 1, settings => Changed#{<<"password">> => <<"x">>}, reset => []}),
    Huge = binary:copy(<<"x">>, 300000),
    {413, _} = json_request(put, "/api/settings", #{padding => Huge}),
    {200, Reset} = json_request(put, "/api/settings",
        #{revision => Revision + 1, settings => Changed, reset => [<<"cache">>]}),
    ?assertEqual(Revision + 2, maps:get(<<"revision">>, Reset)).

trends_have_rfc3339_timestamps(Config) ->
    sql(Config, "CREATE TABLE IF NOT EXISTS query_log_dashboard_test PARTITION OF query_log "
                "DEFAULT"),
    sql(Config, "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode) "
                "VALUES ('192.0.2.1', 'dashboard.example', 1, 'NOERROR', 'NOERROR')"),
    {ok, {{_, 200, _}, _, Body}} = httpc:request(
        get, {"http://127.0.0.1:" ++ integer_to_list(?PORT) ++ "/api/stats/trends", []}, [], []),
    #{<<"trends">> := Rows} = jsx:decode(list_to_binary(Body), [return_maps]),
    ?assert(length(Rows) > 0),
    lists:foreach(fun(#{<<"time">> := Time}) ->
        ?assertMatch({match, _}, re:run(Time,
            <<"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$">>)),
        ?assert(is_integer(calendar:rfc3339_to_system_time(binary_to_list(Time))))
    end, Rows).

unblock_normalizes_and_clears_the_stored_block(Config) ->
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('ads.example.com')"),
    ?assertEqual(200, post("/api/unblock", #{domain => <<"Ads.Example.COM.">>})),
    ?assertEqual([], col(Config, "SELECT domain FROM manual_blocks")),
    ?assertEqual([<<"ads.example.com">>], col(Config, "SELECT domain FROM allowlist")).

%% If adding the allow fails, the block must NOT have been removed: otherwise the
%% domain silently loses both its block and its allow.
unblock_is_atomic(Config) ->
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('ads.example.com')"),
    sql(Config, "ALTER TABLE allowlist RENAME TO allowlist_broken"),
    try
        ?assertEqual(500, post("/api/unblock", #{domain => <<"ads.example.com">>})),
        ?assertEqual([<<"ads.example.com">>], col(Config, "SELECT domain FROM manual_blocks"))
    after
        sql(Config, "ALTER TABLE allowlist_broken RENAME TO allowlist")
    end.

block_normalizes_and_clears_an_allow(Config) ->
    sql(Config, "INSERT INTO allowlist (domain) VALUES ('ads.example.com')"),
    ?assertEqual(200, post("/api/blocks", #{domain => <<"||Ads.Example.com^">>})),
    ?assertEqual([<<"ads.example.com">>], col(Config, "SELECT domain FROM manual_blocks")),
    ?assertEqual([], col(Config, "SELECT domain FROM allowlist")).

threat_block_normalizes_and_clears_an_allow(Config) ->
    sql(Config, "INSERT INTO allowlist (domain) VALUES ('evil.example')"),
    ?assertEqual(200, post("/api/threats/block", #{domain => <<"Evil.EXAMPLE">>})),
    ?assertEqual([<<"evil.example">>], col(Config, "SELECT domain FROM manual_blocks")),
    ?assertEqual([], col(Config, "SELECT domain FROM allowlist")).

delete_endpoints_normalize(Config) ->
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('ads.example.com')"),
    ?assertEqual(200, request(delete, "/api/blocks", #{domain => <<"ADS.example.com.">>})),
    ?assertEqual([], col(Config, "SELECT domain FROM manual_blocks")),
    sql(Config, "INSERT INTO allowlist (domain) VALUES ('ok.example')"),
    ?assertEqual(200, request(delete, "/api/allowlist/OK.Example", none)),
    ?assertEqual([], col(Config, "SELECT domain FROM allowlist")).

client_block_normalizes(Config) ->
    ?assertEqual(200, post("/api/client-blocks", #{client_ip => <<"192.168.1.5">>,
                                                   domain => <<"Games.Example.">>})),
    ?assertEqual([<<"games.example">>], col(Config, "SELECT domain FROM client_blocks")),
    ?assertEqual(200, request(delete, "/api/client-blocks", #{client_ip => <<"192.168.1.5">>,
                                                               domain => <<"GAMES.example">>})),
    ?assertEqual([], col(Config, "SELECT domain FROM client_blocks")).

rewrite_domain_is_normalized(Config) ->
    ?assertEqual(200, post("/api/rewrites", #{domain => <<"NAS.Home.">>, target => <<"192.168.1.5">>})),
    ?assertEqual([<<"nas.home">>], col(Config, "SELECT domain FROM rewrites")).

invalid_domains_are_rejected(Config) ->
    ?assertEqual(400, post("/api/unblock", #{domain => <<"has space.com">>})),
    ?assertEqual(400, post("/api/blocks", #{domain => <<"<b>.com">>})),
    ?assertEqual(400, post("/api/threats/block", #{domain => <<"a b">>})),
    ?assertEqual(400, post("/api/rewrites", #{domain => <<"x y">>, target => <<"1.2.3.4">>})),
    ?assertEqual([], col(Config, "SELECT domain FROM manual_blocks UNION ALL SELECT domain FROM allowlist")).

%% ── helpers ───────────────────────────────────────────────────

post(Path, Body) -> request(post, Path, Body).

request(Method, Path, Body) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path,
    Req = case Body of
        none -> {Url, []};
        _ -> {Url, [], "application/json", jsx:encode(Body)}
    end,
    {ok, {{_, Code, _}, _, _}} = httpc:request(Method, Req, [{timeout, 10000}], []),
    Code.

json_request(Method, Path, Body) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path,
    Req = case Body of
        none -> {Url, []};
        _ -> {Url, [], "application/json", jsx:encode(Body)}
    end,
    {ok, {{_, Code, _}, _, Resp}} = httpc:request(Method, Req, [{timeout, 10000}], []),
    {Code, case Resp of [] -> #{}; _ -> jsx:decode(list_to_binary(Resp), [return_maps]) end}.

%% A fresh connection per call: a connection opened in init_per_suite is linked
%% to a process that exits before the testcases run.
with_direct(Config, Fun) ->
    C = raw_connect(?config(db, Config), ?config(scratch, Config)),
    try Fun(C) after epgsql:close(C) end.

sql(Config, Sql) ->
    case with_direct(Config, fun(C) -> epgsql:squery(C, Sql) end) of
        {ok, _} -> ok;
        {ok, _, _} -> ok;
        Err -> ct:fail({sql_failed, Sql, Err})
    end.

col(Config, Sql) ->
    {ok, _, Rows} = with_direct(Config, fun(C) -> epgsql:squery(C, Sql ++ " ORDER BY 1") end),
    [V || {V} <- Rows].

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
        Pid -> unlink(Pid), exit(Pid, shutdown)
    end.

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

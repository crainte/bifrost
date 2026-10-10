%% "Postgres is control-plane only; DNS MUST survive losing it." (AGENTS.md)
%%
%% Exercised for real: a REAL Postgres scratch database, real Mnesia, the real
%% HTTP router, and the real hydration path in bifrost_blocklist_manager, with a
%% stand-in for the Rust socket that records exactly what this node would send
%% to its own Rust process.
%%
%%  1. Readiness must not wait on Postgres: every pod shares it, so a slow query
%%     marking pods NotReady would take ALL DNS IPs out at once.
%%  2. Operational config (rewrites, allowlist, manual/client blocks, UI-added
%%     blocklists) must still reach Rust when Postgres is down or hung: it is
%%     snapshotted to Mnesia whenever Postgres answers, and the snapshot is used
%%     when it does not.
-module(bifrost_db_resilience_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([readiness_does_not_wait_for_the_database/1,
         pushes_fall_back_to_last_known_config_when_db_is_down/1,
         hydration_completes_from_snapshot_when_db_is_down/1,
         hydration_completes_when_db_hangs/1,
         rejected_settings_block_reload_complete/1]).
-export([fake_rust/1]).

-define(PORT, 18124).

suite() -> [{timetrap, {seconds, 90}}].

all() ->
    [readiness_does_not_wait_for_the_database,
     pushes_fall_back_to_last_known_config_when_db_is_down,
     hydration_completes_from_snapshot_when_db_is_down,
     hydration_completes_when_db_hangs,
     rejected_settings_block_reload_complete].

init_per_suite(Config) ->
    [{ok, _} = application:ensure_all_started(A) || A <- [crypto, epgsql, cowboy, inets]],
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_resil_" ++ integer_to_list(erlang:system_time(millisecond)),
    with_conn(Db, maps:get(name, Db), fun(C) -> {ok, _, _} = epgsql:squery(C, "CREATE DATABASE " ++ Scratch) end),
    CfgPath = filename:join(?config(priv_dir, Config), "resil_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n"
        "{upstreams, [[{address, \"127.0.0.1\"}, {port, 53}]]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    os:unsetenv("BIFROST_CLUSTER_NODES"),
    os:unsetenv("BIFROST_CLUSTER_SERVICE"),
    application:set_env(mnesia, dir, filename:join(?config(priv_dir, Config), "mnesia")),
    ok = bifrost_mnesia:init_tables(),
    {ok, CfgPid} = bifrost_config_server:start_link(),
    unlink(CfgPid),
    Dispatch = cowboy_router:compile(bifrost_router:routes()),
    {ok, _} = cowboy:start_clear(resil_ct_listener, [{port, ?PORT}],
                                 #{env => #{dispatch => Dispatch}}),
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    cowboy:stop_listener(resil_ct_listener),
    stop(bifrost_config_server),
    mnesia:stop(),
    Db = ?config(db, Config),
    with_conn(Db, maps:get(name, Db), fun(C) ->
        epgsql:squery(C, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)")
    end),
    ok.

init_per_testcase(_TC, Config) ->
    start_pool(),
    [sql(Config, "DELETE FROM " ++ T)
     || T <- ["manual_blocks", "allowlist", "client_blocks", "rewrites", "blocklists"]],
    Fake = spawn(?MODULE, fake_rust, [self()]),
    register(bifrost_socket_server, Fake),
    [{fake, Fake} | Config].

end_per_testcase(_TC, Config) ->
    stop(bifrost_blocklist_manager),
    stop(bifrost_dns_settings_server),
    exit(?config(fake, Config), kill),
    catch unregister(bifrost_socket_server),
    stop(bifrost_db_pool),
    persistent_term:erase({bifrost_blocklist_manager, hydrated}),
    ok.

%% ── cases ─────────────────────────────────────────────────────

rejected_settings_block_reload_complete(Config) ->
    put(reject_settings, true),
    exit(?config(fake, Config), kill),
    catch unregister(bifrost_socket_server),
    Fake = spawn(?MODULE, fake_rust, [{reject, self()}]),
    register(bifrost_socket_server, Fake),
    hydrate(),
    Msgs = collect(3000),
    ?assert(lists:any(fun(#{type := T}) -> T =:= <<"apply_dns_settings">>; (_) -> false end, Msgs)),
    ?assertNot(lists:member(#{type => <<"reload_complete">>}, Msgs)),
    ?assertNot(bifrost_blocklist_manager:is_hydrated()).

readiness_does_not_wait_for_the_database(_Config) ->
    persistent_term:put({bifrost_blocklist_manager, hydrated}, true),
    %% Occupy the (single) pool connection with a slow query.
    spawn(fun() -> bifrost_db_pool:query("SELECT pg_sleep(4)") end),
    timer:sleep(200),
    T0 = erlang:monotonic_time(millisecond),
    {Code, Body} = http_get("/api/health"),
    Took = erlang:monotonic_time(millisecond) - T0,
    ?assertEqual(200, Code),
    ?assertMatch(#{<<"status">> := <<"ok">>}, Body),
    ?assert(Took < 1000).

pushes_fall_back_to_last_known_config_when_db_is_down(Config) ->
    seed_operational(Config),
    push_all(),
    Live = collect(),
    stop(bifrost_db_pool),
    push_all(),
    FromSnapshot = collect(),
    [?assertEqual(entries(Type, Live), entries(Type, FromSnapshot))
     || Type <- [<<"load_rewrites">>, <<"load_allowlist">>, <<"load_client_blocks">>]],
    ?assertEqual([[<<"manual.example">>]], loads(<<"manual">>, FromSnapshot)),
    ?assertNotEqual([], entries(<<"load_rewrites">>, FromSnapshot)).

hydration_completes_from_snapshot_when_db_is_down(Config) ->
    seed_operational(Config),
    sql(Config, "INSERT INTO blocklists (name, url, enabled, source) "
                "VALUES ('ui-list', 'http://127.0.0.1:1/never.txt', true, 'ui')"),
    ok = bifrost_mnesia:write_cache("ui-list", [<<"ui-blocked.example">>], <<"\"e\"">>),
    hydrate(),
    WithDb = collect(),
    ?assert(lists:member(#{type => <<"reload_complete">>}, WithDb)),
    stop(bifrost_db_pool),
    hydrate(),
    NoDb = collect(),
    ?assert(lists:member(#{type => <<"reload_complete">>}, NoDb)),
    ?assertEqual([[<<"ui-blocked.example">>]], loads(<<"ui-list">>, NoDb)),
    ?assertEqual(entries(<<"load_rewrites">>, WithDb), entries(<<"load_rewrites">>, NoDb)),
    ?assertNotEqual([], entries(<<"load_rewrites">>, NoDb)).

hydration_completes_when_db_hangs(Config) ->
    seed_operational(Config),
    hydrate(),
    _ = collect(),
    %% The pool's only connection is now stuck for longer than any test timeout.
    spawn(fun() -> bifrost_db_pool:query("SELECT pg_sleep(120)") end),
    timer:sleep(200),
    hydrate(),
    Msgs = collect(45000),
    ?assert(lists:member(#{type => <<"reload_complete">>}, Msgs)),
    ?assertNotEqual([], entries(<<"load_rewrites">>, Msgs)),
    stop(bifrost_db_pool),
    sql(Config, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE query LIKE 'SELECT pg_sleep(120)%'").

%% ── helpers ───────────────────────────────────────────────────

seed_operational(Config) ->
    sql(Config, "INSERT INTO rewrites (domain, target) VALUES ('nas.home', '192.168.1.5')"),
    sql(Config, "INSERT INTO allowlist (domain) VALUES ('ok.example')"),
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('manual.example')"),
    sql(Config, "INSERT INTO client_blocks (client_ip, domain) VALUES ('192.168.1.9', 'kid.example')").

push_all() ->
    bifrost_api_handler:push_rewrites(),
    bifrost_api_handler:push_allowlist(),
    bifrost_api_handler:push_manual_blocks(),
    bifrost_api_handler:push_client_blocks().

hydrate() ->
    case whereis(bifrost_dns_settings_server) of
        undefined -> {ok, _} = gen_server:start({local, bifrost_dns_settings_server},
                                                bifrost_dns_settings_server, [], []);
        _ -> ok
    end,
    case whereis(bifrost_blocklist_manager) of
        undefined ->
            {ok, Pid} = gen_server:start({local, bifrost_blocklist_manager},
                                         bifrost_blocklist_manager, [], []),
            Pid;
        Pid -> Pid
    end,
    bifrost_blocklist_manager:on_client_connected().

fake_rust({reject, Collector}) ->
    receive
        {'$gen_call', From, {send, Data}} ->
            Collector ! {rust_msg, Data},
            gen_server:reply(From, ok),
            case Data of
                #{type := <<"apply_dns_settings">>, revision := R, fingerprint := F} ->
                    bifrost_dns_settings_server:handle_ack(fake_connection,
                        #{<<"type">> => <<"dns_settings_rejected">>, <<"revision">> => R,
                          <<"fingerprint">> => F, <<"error">> => <<"test rejection">>});
                _ -> ok
            end,
            fake_rust({reject, Collector});
        {'$gen_call', From, connection_id} ->
            gen_server:reply(From, fake_connection),
            fake_rust({reject, Collector})
    end;
fake_rust(Collector) ->
    receive
        {'$gen_call', From, {send, Data}} ->
            Collector ! {rust_msg, Data},
            gen_server:reply(From, ok),
            case Data of
                #{type := <<"apply_dns_settings">>, revision := R, fingerprint := F} ->
                    bifrost_dns_settings_server:handle_ack(fake_connection,
                        #{<<"type">> => <<"dns_settings_applied">>,
                          <<"revision">> => R, <<"fingerprint">> => F});
                _ -> ok
            end,
            fake_rust(Collector);
        {'$gen_call', From, connection_id} ->
            gen_server:reply(From, fake_connection),
            fake_rust(Collector)
    end.

collect() -> collect(15000).

%% Everything sent to Rust until a quiet period, or until reload_complete.
collect(Timeout) -> collect(Timeout, []).
collect(Timeout, Acc) ->
    receive
        {rust_msg, #{type := <<"reload_complete">>} = M} -> lists:reverse([M | Acc]);
        {rust_msg, M} -> collect(Timeout, [M | Acc])
    after Timeout -> lists:reverse(Acc)
    end.

entries(Type, Msgs) ->
    [lists:sort(maps:get(entries, M)) || M <- Msgs, maps:get(type, M) =:= Type].

loads(ListId, Msgs) ->
    [lists:sort(maps:get(entries, M)) || M <- Msgs, maps:get(type, M) =:= <<"load_blocklist">>,
                                         maps:get(list_id, M) =:= ListId].

http_get(Path) ->
    {ok, {{_, Code, _}, _, Body}} =
        httpc:request(get, {"http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path, []},
                      [{timeout, 10000}], [{body_format, binary}]),
    {Code, jsx:decode(Body, [return_maps])}.

start_pool() ->
    {ok, Pid} = bifrost_db_pool:start_link(),
    unlink(Pid),
    wait_connected(50).

wait_connected(0) -> ct:fail(db_never_connected);
wait_connected(N) ->
    case catch bifrost_db_pool:query("SELECT 1 FROM rewrites LIMIT 1") of
        {ok, _, _} -> ok;
        _ -> timer:sleep(200), wait_connected(N - 1)
    end.

sql(Config, Sql) ->
    Db = ?config(db, Config),
    case with_conn(Db, ?config(scratch, Config), fun(C) -> epgsql:squery(C, Sql) end) of
        {ok, _} -> ok;
        {ok, _, _} -> ok;
        Err -> ct:fail({sql_failed, Sql, Err})
    end.

with_conn(Db, Name, Fun) ->
    {ok, C} = epgsql:connect(maps:get(host, Db), maps:get(user, Db), maps:get(pass, Db),
                             [{port, maps:get(port, Db)}, {database, Name}]),
    try Fun(C) after epgsql:close(C) end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            Ref = monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> ok end
    end.

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

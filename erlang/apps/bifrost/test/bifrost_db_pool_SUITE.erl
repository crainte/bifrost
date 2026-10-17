%% Common Test suite for bifrost_db_pool against a REAL Postgres. Verifies:
%%  - the pool connects using the password from BIFROST_DB_PASSWORD (the secret
%%    path), NOT from the config term (which deliberately omits it);
%%  - query/1 and equery/2 execute real SQL and return real rows;
%%  - migrations ran, creating the expected schema.
%%
%% Requires a reachable Postgres. Connection is taken from env so the same suite
%% runs in CI/dev:
%%   BIFROST_TEST_DB_HOST (default "postgres"), BIFROST_TEST_DB_PORT (5432),
%%   BIFROST_TEST_DB_NAME (bifrost), BIFROST_TEST_DB_USER (bifrost),
%%   BIFROST_TEST_DB_PASSWORD (bifrost).
-module(bifrost_db_pool_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([connects_via_env_password/1, query_returns_rows/1,
          equery_binds_params/1, migrations_created_schema/1,
          ptr_warmer_selects_missing_and_stale_entries/1]).

all() ->
    [connects_via_env_password, query_returns_rows,
     equery_binds_params, migrations_created_schema,
     ptr_warmer_selects_missing_and_stale_entries].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    Host = getenv("BIFROST_TEST_DB_HOST", "postgres"),
    Port = list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
    Name = getenv("BIFROST_TEST_DB_NAME", "bifrost"),
    User = getenv("BIFROST_TEST_DB_USER", "bifrost"),
    Pass = getenv("BIFROST_TEST_DB_PASSWORD", "bifrost"),

    %% Write a config file with the DB block but NO password — the pool must get
    %% the password from BIFROST_DB_PASSWORD. This is the security contract we're
    %% verifying: secrets come from env, not the (GitOps) config.
    Dir = ?config(priv_dir, Config),
    CfgPath = filename:join(Dir, "test_config.yaml"),
    Cfg = io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n",
        [Host, Port, Name, User]),
    ok = file:write_file(CfgPath, Cfg),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", Pass),

    %% start_link links the server to THIS (init_per_suite) process, which exits
    %% before the testcases run — killing the server. Unlink so both survive into
    %% the testcase processes; end_per_suite stops them explicitly.
    {ok, CfgPid} = bifrost_config_server:start_link(),
    erlang:unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    erlang:unlink(PoolPid),
    ok = wait_connected(50),
    Config.

end_per_suite(_Config) ->
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

%% The pool reached "connected" state — only possible if the env password was
%% used, since the config term carried none.
connects_via_env_password(_Config) ->
    %% query/1 uses squery -> all columns come back as text binaries.
    {ok, _Cols, [{<<"1">>}]} = bifrost_db_pool:query("SELECT 1"),
    ok.

query_returns_rows(_Config) ->
    {ok, _Cols, Rows} = bifrost_db_pool:query("SELECT 42 AS answer"),
    ?assertEqual([{<<"42">>}], Rows).

%% Parameterized query binds params and returns typed values (equery uses the
%% binary protocol — proves epgsql 4.8.0's send path works end to end).
equery_binds_params(_Config) ->
    {ok, _Cols, Rows} = bifrost_db_pool:equery("SELECT $1::int + $2::int", [40, 2]),
    ?assertEqual([{42}], Rows).

%% Migrations ran on connect: the core tables must exist. Asserts against the
%% real schema, so a broken/missing migration fails here.
migrations_created_schema(_Config) ->
    Expected = ["query_log", "ptr_cache", "settings", "blocklists",
                "allowlist", "rewrites", "clients", "manual_blocks"],
    lists:foreach(fun(T) ->
        {ok, _, [{Exists}]} = bifrost_db_pool:equery(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_name = $1)", [list_to_binary(T)]),
        ?assertEqual(true, Exists)
    end, Expected),
    %% ptr_ttl_seconds seed (migration 008) is present.
    {ok, _, [{Val}]} = bifrost_db_pool:equery(
        "SELECT value FROM settings WHERE key = $1", [<<"ptr_ttl_seconds">>]),
    ?assertEqual(<<"21600">>, Val).

ptr_warmer_selects_missing_and_stale_entries(_Config) ->
    Key = {bifrost_dns_settings_server, effective},
    persistent_term:put(Key, #{settings => #{<<"reverse_dns">> => #{
        <<"enrichment_enabled">> => true,
        <<"resolvers">> => [#{<<"address">> => <<"127.0.0.1">>, <<"port">> => 53}],
        <<"positive_ttl_seconds">> => 60, <<"negative_ttl_seconds">> => 5}}}),
    try
        {ok, _} = bifrost_db_pool:query("DELETE FROM ptr_cache"),
        {ok, _} = bifrost_db_pool:query("DELETE FROM query_log"),
        _ = bifrost_query_writer:maintain_partitions(undefined),
        {ok, _} = bifrost_db_pool:equery(
            "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode) VALUES "
            "($1, 'missing.example', 1, 'NOERROR', 'NOERROR'), "
            "($2, 'stale-positive.example', 1, 'NOERROR', 'NOERROR'), "
            "($3, 'fresh-positive.example', 1, 'NOERROR', 'NOERROR'), "
            "($4, 'stale-negative.example', 1, 'NOERROR', 'NOERROR')",
            [ip(1), ip(2), ip(3), ip(4)]),
        Provenance = bifrost_ptr:visible_provenance(),
        {ok, _} = bifrost_db_pool:equery(
            "INSERT INTO ptr_cache (ip, name, looked_up, provenance) VALUES "
            "($1, 'stale', now() - interval '61 seconds', $4), "
            "($2, 'fresh', now() - interval '59 seconds', $4), "
            "($3, NULL, now() - interval '6 seconds', $4)",
            [ip(2), ip(3), ip(4), Provenance]),
        ?assertEqual({ok, 3}, bifrost_ptr:warm())
    after
        persistent_term:erase(Key)
    end.

%% ── helpers ───────────────────────────────────────────────────

ip(N) -> {192, 0, 2, N}.

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

wait_connected(0) -> {error, timeout};
wait_connected(N) ->
    case bifrost_db_pool:query("SELECT 1") of
        {ok, _, _} -> ok;
        _ -> timer:sleep(200), wait_connected(N - 1)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

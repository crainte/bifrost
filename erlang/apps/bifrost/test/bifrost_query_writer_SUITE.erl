%% bifrost_query_writer against a REAL Postgres scratch database.
%%
%% The query log is the only per-query write path, so it must keep up with DNS
%% load and must not be stalled by, or stall, anything else:
%%  - events persist with every field, in batches, and one malformed event
%%    cannot drop the rest of its batch;
%%  - writes have their own connection, so a slow dashboard query on the shared
%%    pool does not hold up logging;
%%  - while Postgres is down the buffer is BOUNDED (no unbounded mailbox/heap
%%    growth) and the outage is logged once, not once per query;
%%  - dashboard counts come from one pass over query_log and stay correct.
-module(bifrost_query_writer_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([events_are_persisted_with_all_fields/1,
         bad_event_does_not_drop_the_rest_of_the_batch/1,
         writes_do_not_wait_behind_a_slow_ui_query/1,
         buffer_is_bounded_while_db_is_down/1,
         outage_warnings_are_rate_limited/1,
         partition_is_created_after_booting_with_db_down/1,
         dashboard_counts_are_correct/1]).
-export([log/2]).

-define(PORT, 18125).

suite() -> [{timetrap, {seconds, 120}}].

all() ->
    [events_are_persisted_with_all_fields,
     bad_event_does_not_drop_the_rest_of_the_batch,
     writes_do_not_wait_behind_a_slow_ui_query,
     buffer_is_bounded_while_db_is_down,
     outage_warnings_are_rate_limited,
     partition_is_created_after_booting_with_db_down,
     dashboard_counts_are_correct].

init_per_suite(Config) ->
    [{ok, _} = application:ensure_all_started(A) || A <- [crypto, epgsql, cowboy, inets]],
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_qw_" ++ integer_to_list(erlang:system_time(millisecond)),
    with_conn(Db, maps:get(name, Db), fun(C) -> {ok, _, _} = epgsql:squery(C, "CREATE DATABASE " ++ Scratch) end),
    CfgPath = filename:join(?config(priv_dir, Config), "qw_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    {ok, CfgPid} = bifrost_config_server:start_link(),
    unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    unlink(PoolPid),
    ok = wait_until(fun() -> pool_ready(bifrost_db_pool) end),
    Dispatch = cowboy_router:compile(bifrost_router:routes()),
    {ok, _} = cowboy:start_clear(qw_ct_listener, [{port, ?PORT}], #{env => #{dispatch => Dispatch}}),
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    cowboy:stop_listener(qw_ct_listener),
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    Db = ?config(db, Config),
    with_conn(Db, maps:get(name, Db), fun(C) ->
        epgsql:squery(C, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)")
    end),
    ok.

init_per_testcase(_TC, Config) ->
    start_writer_pool(),
    {ok, W} = bifrost_query_writer:start_link(),
    unlink(W),
    %% The writer creates the current month's partition on its first flush.
    %% Clear FIRST: rows left by the previous case would otherwise satisfy the
    %% wait before this warm-up event lands, and it would land after the DELETE.
    sql(Config, "DELETE FROM query_log"),
    cast(event(#{<<"domain">> => <<"warmup.example">>})),
    ok = wait_until(fun() -> count(Config) =:= 1 end),
    sql(Config, "DELETE FROM query_log"),
    Config.

end_per_testcase(_TC, _Config) ->
    stop(bifrost_query_writer),
    stop(bifrost_db_writer),
    catch logger:remove_handler(qw_ct_counter),
    case whereis(bifrost_db_pool) of
        undefined ->
            {ok, P} = bifrost_db_pool:start_link(),
            unlink(P),
            ok = wait_until(fun() -> pool_ready(bifrost_db_pool) end);
        _ -> ok
    end.

%% A real outage takes out every connection, not just the writer's.
db_outage() ->
    stop(bifrost_db_writer),
    stop(bifrost_db_pool).

%% ── cases ─────────────────────────────────────────────────────

events_are_persisted_with_all_fields(Config) ->
    [cast(event(#{<<"domain">> => <<"d", (integer_to_binary(N))/binary, ".example">>}))
     || N <- lists:seq(1, 250)],
    cast(event(#{<<"domain">> => <<"full.example">>, <<"action">> => <<"BIFROST_BLOCK">>,
                 <<"client_rcode">> => <<"NOERROR">>, <<"ede_code">> => 15,
                 <<"list_id">> => <<"hagezi">>, <<"latency_us">> => null,
                 <<"response_records">> => [#{<<"rtype">> => <<"A">>, <<"value">> => <<"0.0.0.0">>}]})),
    ok = wait_until(fun() -> count(Config) =:= 251 end),
    [{Ip, Action, Rcode, Ede, List, Lat, Recs}] = rows(Config,
        "SELECT host(client_ip), action::text, client_rcode::text, ede_code::text, list_id, "
        "latency_us::text, response_records::text FROM query_log WHERE domain = 'full.example'"),
    ?assertEqual({<<"192.168.1.42">>, <<"BIFROST_BLOCK">>, <<"NOERROR">>, <<"15">>, <<"hagezi">>, null},
                 {Ip, Action, Rcode, Ede, List, Lat}),
    ?assertMatch([#{<<"value">> := <<"0.0.0.0">>}], jsx:decode(Recs, [return_maps])).

bad_event_does_not_drop_the_rest_of_the_batch(Config) ->
    cast(event(#{<<"domain">> => <<"good1.example">>})),
    cast(event(#{<<"domain">> => <<"bad.example">>, <<"action">> => <<"NOT_AN_RCODE">>})),
    cast(event(#{<<"domain">> => <<"good2.example">>})),
    ok = wait_until(fun() -> count(Config) =:= 2 end),
    timer:sleep(1000),
    ?assertEqual([<<"good1.example">>, <<"good2.example">>],
                 [D || {D} <- rows(Config, "SELECT domain FROM query_log ORDER BY domain")]).

writes_do_not_wait_behind_a_slow_ui_query(Config) ->
    spawn(fun() -> bifrost_db_pool:query("SELECT pg_sleep(6)") end),
    timer:sleep(200),
    T0 = erlang:monotonic_time(millisecond),
    cast(event(#{<<"domain">> => <<"fast.example">>})),
    ok = wait_until(fun() -> count(Config) =:= 1 end, 3000),
    ?assert(erlang:monotonic_time(millisecond) - T0 < 3000).

buffer_is_bounded_while_db_is_down(Config) ->
    db_outage(),
    Max = bifrost_query_writer:max_buffer(),
    [cast(event(#{})) || _ <- lists:seq(1, Max + 5000)],
    timer:sleep(1500),
    #{buffered := Buffered, dropped := Dropped} = bifrost_query_writer:stats(),
    ?assert(Buffered =< Max),
    ?assert(Dropped >= 5000),
    %% Recovery: what was buffered is written once Postgres is back.
    start_writer_pool(),
    ok = wait_until(fun() -> count(Config) =:= Buffered end, 60000).

outage_warnings_are_rate_limited(_Config) ->
    ok = logger:add_handler(qw_ct_counter, ?MODULE, #{config => #{pid => self()}, level => warning}),
    db_outage(),
    [begin cast(event(#{})), timer:sleep(20) end || _ <- lists:seq(1, 150)],
    timer:sleep(1000),
    Warnings = count_warnings(0),
    ?assert(Warnings =< 2).

%% A pod that boots while Postgres is down cannot create this month's
%% partition. That must be retried once Postgres is back, not recorded as done:
%% otherwise every event lands in a missing partition and is dropped for the
%% rest of the month.
partition_is_created_after_booting_with_db_down(Config) ->
    stop(bifrost_query_writer),
    {{Y, M, _}, _} = calendar:universal_time(),
    Current = lists:flatten(io_lib:format("query_log_~4..0B_~2..0B", [Y, M])),
    sql(Config, "DROP TABLE IF EXISTS " ++ Current),
    db_outage(),
    {ok, W} = bifrost_query_writer:start_link(),
    unlink(W),
    cast(event(#{<<"domain">> => <<"after-outage.example">>})),
    timer:sleep(1500),
    {ok, P} = bifrost_db_pool:start_link(),
    unlink(P),
    ok = wait_until(fun() -> pool_ready_any(bifrost_db_pool) end),
    start_writer_pool_any(),
    ok = wait_until(fun() -> count(Config) =:= 1 end, 20000).

dashboard_counts_are_correct(Config) ->
    Seed = [{<<"BIFROST_BLOCK">>, 4}, {<<"BIFROST_CACHE">>, 3}, {<<"BIFROST_ALLOW">>, 2},
            {<<"BIFROST_RW">>, 1}, {<<"NOERROR">>, 5}, {<<"NXDOMAIN">>, 2},
            {<<"SERVFAIL">>, 1}, {<<"REFUSED">>, 1}],
    [cast(event(#{<<"action">> => A})) || {A, N} <- Seed, _ <- lists:seq(1, N)],
    ok = wait_until(fun() -> count(Config) =:= 19 end),
    {ok, {{_, 200, _}, _, Body}} = httpc:request(get,
        {"http://127.0.0.1:" ++ integer_to_list(?PORT) ++ "/api/stats", []}, [], [{body_format, binary}]),
    S = jsx:decode(Body, [return_maps]),
    ?assertEqual({4, 3, 2, 1, 5, 4}, {maps:get(<<"blocked">>, S), maps:get(<<"cached">>, S),
                                      maps:get(<<"allowed">>, S), maps:get(<<"rewritten">>, S),
                                      maps:get(<<"forwarded">>, S), maps:get(<<"upstream_errors">>, S)}),
    ?assertEqual({2, 1}, {maps:get(<<"nxdomain">>, S), maps:get(<<"servfail">>, S)}).

%% ── logger handler (counts query_writer warnings) ────────────

%% Matched on the emitting PROCESS: plain logger:warning/2 calls carry no mfa
%% metadata, so filtering on mfa would count nothing and pass vacuously.
log(#{level := warning, meta := #{pid := From}}, #{config := #{pid := Pid}}) ->
    case whereis(bifrost_query_writer) of
        From -> Pid ! qw_warning;
        _ -> ok
    end;
log(_, _) ->
    ok.

count_warnings(N) ->
    receive qw_warning -> count_warnings(N + 1)
    after 0 -> N
    end.

%% ── helpers ───────────────────────────────────────────────────

event(Overrides) ->
    maps:merge(#{<<"type">> => <<"query_event">>, <<"client_ip">> => <<"192.168.1.42">>,
                 <<"domain">> => <<"x.example">>, <<"qtype">> => 1,
                 <<"action">> => <<"NOERROR">>, <<"client_rcode">> => <<"NOERROR">>,
                 <<"ede_code">> => null, <<"list_id">> => null, <<"latency_us">> => 1200,
                 <<"queried_at">> => erlang:system_time(second)}, Overrides).

cast(E) -> gen_server:cast(bifrost_query_writer, {query_event, E}).

start_writer_pool() ->
    {ok, P} = bifrost_db_pool:start_link(bifrost_db_writer),
    unlink(P),
    ok = wait_until(fun() -> pool_ready(bifrost_db_writer) end).

%% Ready = connected, whether or not query_log currently has a partition.
pool_ready_any(Pool) ->
    case catch bifrost_db_pool:pool_query(Pool, "SELECT 1", 2000) of
        {ok, _, _} -> true;
        _ -> false
    end.

start_writer_pool_any() ->
    {ok, P} = bifrost_db_pool:start_link(bifrost_db_writer),
    unlink(P),
    ok = wait_until(fun() -> pool_ready_any(bifrost_db_writer) end).

pool_ready(Pool) ->
    case catch bifrost_db_pool:pool_query(Pool, "SELECT 1 FROM query_log LIMIT 1", 2000) of
        {ok, _, _} -> true;
        _ -> false
    end.

count(Config) ->
    [{N}] = rows(Config, "SELECT count(*)::text FROM query_log"),
    binary_to_integer(N).

rows(Config, Sql) ->
    Db = ?config(db, Config),
    {ok, _, R} = with_conn(Db, ?config(scratch, Config), fun(C) -> epgsql:squery(C, Sql) end),
    R.

sql(Config, Sql) ->
    Db = ?config(db, Config),
    with_conn(Db, ?config(scratch, Config), fun(C) -> epgsql:squery(C, Sql) end).

with_conn(Db, Name, Fun) ->
    {ok, C} = epgsql:connect(maps:get(host, Db), maps:get(user, Db), maps:get(pass, Db),
                             [{port, maps:get(port, Db)}, {database, Name}]),
    try Fun(C) after epgsql:close(C) end.

wait_until(Fun) -> wait_until(Fun, 20000).
wait_until(Fun, T) when T =< 0 -> case Fun() of true -> ok; _ -> {error, timeout} end;
wait_until(Fun, T) ->
    case catch Fun() of
        true -> ok;
        _ -> timer:sleep(100), wait_until(Fun, T - 100)
    end.

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

%% Common Test suite for the query_log partition retention in
%% bifrost_query_writer, against a REAL Postgres. This code issues DROP TABLE,
%% so every test here exists to prove it cannot destroy data it must keep:
%%
%%  1. drops_only_partitions_older_than_retention — the cutoff is an absolute
%%     month ordinal (Year*12 + Month - Keep) precisely so December/January does
%%     not need special casing. A wrong comparison (=< instead of <) or a wrong
%%     cutoff (+Keep instead of -Keep) silently deletes months that are still
%%     inside the retention window. The expected surviving/dropped sets are
%%     recomputed here from the cutoff rule and compared as whole sets, so any
%%     drift by a single month fails.
%%  2. never_drops_current_or_next_partition — the data-loss guard. maintain
%%     creates the current and next month partitions and then prunes in the same
%%     pass; an off-by-one in the cutoff would drop the partition the writer is
%%     inserting into right now, at the most aggressive setting (Keep = 1).
%%  3. retention_zero_keeps_everything — 0 is the documented "keep forever"
%%     escape hatch and the pre-retention behaviour. If retention_months/0 ever
%%     ignores the settings row and falls through to the default, an operator
%%     who opted out loses history.
%%  4. missing_or_invalid_setting_falls_back_to_default — the settings row is
%%     operator-editable, so it can be absent or garbage. Either must yield the
%%     6-month default, never a crash and never 0-by-accident (which would
%%     silently disable retention) or a huge value.
%%  5. only_touches_query_log_partitions — existing_partitions/0 enumerates via
%%     pg_inherits rather than globbing relnames. A name glob would match any
%%     unrelated table that happens to be called query_log_YYYY_MM and DROP it.
%%  6. maintain_partitions_is_skipped_within_the_same_month — upkeep used to run
%%     on EVERY flush (hundreds of times a second). It now returns the month it
%%     maintained and short-circuits until that month rolls over.
%%
%% Requires a reachable Postgres. Connection is taken from env so the same suite
%% runs in CI/dev:
%%   BIFROST_TEST_DB_HOST (default "postgres"), BIFROST_TEST_DB_PORT (5432),
%%   BIFROST_TEST_DB_NAME (bifrost), BIFROST_TEST_DB_USER (bifrost),
%%   BIFROST_TEST_DB_PASSWORD (bifrost).
%%
%% ISOLATION: the target server is the live dev database, which has a real
%% query_log with real partitions holding real rows. A scratch SCHEMA is not
%% enough here, for two reasons that are properties of the code under test:
%%   - ensure_partition/2 guards with "SELECT 1 FROM pg_class WHERE relname =
%%     'query_log_YYYY_MM'", which is database-wide, not schema-scoped. The live
%%     public schema already holds the current and next month partitions, so
%%     inside a scratch schema maintain_partitions/1 would create nothing and
%%     tests 2 and 6 would assert on a no-op.
%%   - existing_partitions/0 matches the parent by "p.relname = 'query_log'",
%%     also unqualified, so it would enumerate the LIVE partitions and feed
%%     their names to DROP TABLE, with only search_path standing between the
%%     test and real data loss.
%% So the suite creates a throwaway DATABASE (bifrost_ct_ret_<ts>) and points
%% the pool at it: the live query_log then lives in a different database and is
%% unreachable by any statement this code can issue. Inside it, public is
%% dropped and a single ct_ret schema is recreated before every testcase (one
%% schema, not one per case, because that database-wide pg_class check would
%% otherwise leak partition names between cases). end_per_suite drops the
%% database.
-module(bifrost_retention_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([drops_only_partitions_older_than_retention/1,
         never_drops_current_or_next_partition/1,
         retention_zero_keeps_everything/1,
         missing_or_invalid_setting_falls_back_to_default/1,
         only_touches_query_log_partitions/1,
         maintain_partitions_is_skipped_within_the_same_month/1]).

-define(SCHEMA, "ct_ret").
-define(DEFAULT_RETENTION_MONTHS, 6).

all() ->
    [drops_only_partitions_older_than_retention,
     never_drops_current_or_next_partition,
     retention_zero_keeps_everything,
     missing_or_invalid_setting_falls_back_to_default,
     only_touches_query_log_partitions,
     maintain_partitions_is_skipped_within_the_same_month].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(epgsql),
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    %% Unique per run so a crashed previous run cannot collide with this one.
    Scratch = "bifrost_ct_ret_" ++ integer_to_list(erlang:system_time(millisecond)),
    Admin = raw_connect(Db),
    sq(Admin, "CREATE DATABASE " ++ Scratch),
    ok = epgsql:close(Admin),

    %% Point the pool at the scratch database. Password comes from the env, as
    %% in production; the config term carries none.
    CfgPath = filename:join(?config(priv_dir, Config), "retention_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),

    %% start_link links to THIS process, which exits before the testcases run.
    %% Unlink so both survive; end_per_suite stops them explicitly.
    {ok, CfgPid} = bifrost_config_server:start_link(),
    erlang:unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    erlang:unlink(PoolPid),
    ok = wait_connected(50),

    %% The pool ran the real migrations into public on connect. Drop it: the
    %% scratch database must contain exactly one query_log, ours, so neither the
    %% unqualified pg_class check nor the unqualified pg_inherits parent lookup
    %% can see anything but the schema under test.
    pq("DROP SCHEMA IF EXISTS public CASCADE"),
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    Admin = raw_connect(?config(db, Config)),
    %% FORCE: the pool's epgsql process may not have finished closing.
    sq(Admin, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)"),
    ok = epgsql:close(Admin),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

%% One schema, wiped between cases, plus a fresh partitioned query_log and
%% settings table. search_path is per-connection and the pool holds a single
%% long-lived one, so it is set through the pool and then read back — if a
%% reconnect ever dropped it we would be issuing DROP TABLE against whatever
%% the default search_path resolves to, and the suite must refuse to continue.
init_per_testcase(_Case, Config) ->
    pq("DROP SCHEMA IF EXISTS " ?SCHEMA " CASCADE"),
    pq("CREATE SCHEMA " ?SCHEMA),
    pq("SET search_path TO " ?SCHEMA),
    case pq("SELECT current_schema()") of
        {ok, _, [{<<?SCHEMA>>}]} -> ok;
        Other -> ct:fail({search_path_not_isolated, Other})
    end,
    pq("CREATE TABLE query_log ("
       "  id BIGSERIAL,"
       "  domain TEXT NOT NULL,"
       "  queried_at TIMESTAMPTZ NOT NULL DEFAULT now()"
       ") PARTITION BY RANGE (queried_at)"),
    pq("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    Config.

%% ── 1: the cutoff ─────────────────────────────────────────────
%% Ten months around a fixed reference month, plus the current and next month so
%% the recent end of the range is populated too. Keep = 3 against a reference of
%% 2024-07 means everything strictly before 2024-04 goes and 2024-04 itself
%% stays. Both sets are derived from the cutoff rule and compared as sets, so
%% "=<" instead of "<" (2024-04 dies) and "+Keep" instead of "-Keep" (almost
%% everything dies) both fail here rather than being absorbed by a hand-written
%% expectation.
drops_only_partitions_older_than_retention(_Config) ->
    Ref = {2024, 7},
    Keep = 3,
    Now = current_month(),
    All = lists:usort(lists:seq(ord(Ref) - 6, ord(Ref) + 3)
                      ++ [ord(Now), ord(Now) + 1]),
    [create_partition(unord(O)) || O <- All],
    set_retention(Keep),

    Cutoff = ord(Ref) - Keep,
    Survivors = [pname(unord(O)) || O <- All, O >= Cutoff],
    Doomed = [pname(unord(O)) || O <- All, O < Cutoff],
    %% Guards against a vacuous run: the fixture must actually straddle the
    %% cutoff, or "nothing was dropped" would pass trivially.
    ?assertNotEqual([], Doomed),
    ?assertNotEqual([], Survivors),
    ?assertEqual(lists:sort(Survivors ++ Doomed), partitions()),

    ok = bifrost_query_writer:drop_expired_partitions(2024, 7),

    ?assertEqual(lists:sort(Survivors), partitions()),
    ?assertEqual([], [N || N <- Doomed, table_exists(N)]).

%% ── 2: the data-loss guard ────────────────────────────────────
%% Keep = 1 is the most aggressive setting an operator can pick without
%% disabling retention. maintain_partitions/1 creates the current and next month
%% and prunes in the same pass, so an off-by-one in the cutoff deletes the
%% partition being written to. The stale partition is here so the test cannot
%% pass by retention simply not running.
never_drops_current_or_next_partition(_Config) ->
    Now = current_month(),
    Next = unord(ord(Now) + 1),
    Stale = unord(ord(Now) - 5),
    create_partition(Stale),
    set_retention(1),

    ?assertEqual(Now, bifrost_query_writer:maintain_partitions(undefined)),

    ?assert(table_exists(pname(Now))),
    ?assert(table_exists(pname(Next))),
    ?assertNot(table_exists(pname(Stale))),
    ?assertEqual(lists:sort([pname(Now), pname(Next)]), partitions()).

%% ── 3: the opt-out ────────────────────────────────────────────
%% 0 means keep forever. Every partition here is ancient, so if the setting is
%% ignored (or read as the default) they all disappear.
retention_zero_keeps_everything(_Config) ->
    Old = [{2001, M} || M <- lists:seq(1, 5)],
    [create_partition(P) || P <- Old],
    set_retention(0),
    Before = partitions(),
    ?assertEqual(lists:sort([pname(P) || P <- Old]), Before),

    {Y, M} = current_month(),
    ok = bifrost_query_writer:drop_expired_partitions(Y, M),

    ?assertEqual(Before, partitions()).

%% ── 4: operator-editable setting ──────────────────────────────
%% The row is edited by humans through the UI, so it can be missing or garbage.
%% Both must land on the documented default instead of crashing the writer. The
%% real-value case is asserted first so a hardcoded default cannot pass.
missing_or_invalid_setting_falls_back_to_default(_Config) ->
    set_retention(11),
    ?assertEqual(11, bifrost_query_writer:retention_months()),

    pq("DELETE FROM settings WHERE key = 'query_log_retention_months'"),
    ?assertEqual(?DEFAULT_RETENTION_MONTHS, bifrost_query_writer:retention_months()),

    set_retention("abc"),
    ?assertEqual(?DEFAULT_RETENTION_MONTHS, bifrost_query_writer:retention_months()).

%% ── 5: pg_inherits, not a name glob ───────────────────────────
%% The decoy is a plain table whose name matches the partition pattern exactly.
%% Enumerating partitions by relname LIKE 'query_log_%' would select it for
%% DROP; going through pg_inherits cannot, because it is not a child of
%% query_log. The genuine old partition next to it proves the pass ran at all.
only_touches_query_log_partitions(_Config) ->
    Real = {2000, 1},
    Decoy = "query_log_1999_01",
    create_partition(Real),
    pq("CREATE TABLE " ++ Decoy ++ " (id BIGSERIAL, note TEXT)"),
    pq("INSERT INTO " ++ Decoy ++ " (note) VALUES ('not a partition')"),
    set_retention(1),
    ?assert(table_exists(Decoy)),
    ?assertEqual([pname(Real)], partitions()),

    {Y, M} = current_month(),
    ok = bifrost_query_writer:drop_expired_partitions(Y, M),

    ?assertNot(table_exists(pname(Real))),
    ?assert(table_exists(Decoy)),
    %% Still a standalone table with its row, not silently re-created.
    ?assertEqual({ok, [{<<"not a partition">>}]},
                 begin {ok, _, R} = pq("SELECT note FROM " ++ Decoy), {ok, R} end).

%% ── 6: the flush-path short circuit ───────────────────────────
%% Upkeep ran on every flush before; it now returns the maintained month and
%% skips while that month still matches. "Skipped" is proven observably: the
%% current-month partition is deleted behind the module's back and a second call
%% with the matching month must NOT bring it back. The final call with undefined
%% shows the recreate path is alive, so the missing partition is the skip and
%% not a broken ensure_partition/2.
maintain_partitions_is_skipped_within_the_same_month(_Config) ->
    set_retention(0),
    {Y, M} = bifrost_query_writer:maintain_partitions(undefined),
    ?assertEqual(current_month(), {Y, M}),
    Name = pname({Y, M}),
    ?assert(table_exists(Name)),

    pq("DROP TABLE " ++ Name),
    ?assertNot(table_exists(Name)),

    ?assertEqual({Y, M}, bifrost_query_writer:maintain_partitions({Y, M})),
    ?assertNot(table_exists(Name)),

    ?assertEqual({Y, M}, bifrost_query_writer:maintain_partitions(undefined)),
    ?assert(table_exists(Name)).

%% ── helpers ───────────────────────────────────────────────────

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

raw_connect(#{host := H, port := P, name := D, user := U, pass := PW}) ->
    {ok, C} = epgsql:connect(H, U, PW, [{port, P}, {database, D}, {timeout, 5000}]),
    C.

sq(C, Sql) ->
    case epgsql:squery(C, Sql) of
        {ok, _} = R -> R;
        {ok, _, _} = R -> R;
        Other -> ct:fail({sql_failed, Sql, Other})
    end.

%% Everything the tests do goes through the pool, on the same connection the
%% code under test uses — that is what makes the search_path isolation hold.
pq(Sql) ->
    case bifrost_db_pool:query(Sql) of
        {ok, _} = R -> R;
        {ok, _, _} = R -> R;
        Other -> ct:fail({sql_failed, Sql, Other})
    end.

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

%% Absolute month ordinals, so arithmetic across year boundaries is trivial and
%% the test does its own month maths rather than borrowing next_month/2 from the
%% module under test.
ord({Y, M}) -> Y * 12 + M.
unord(O) -> {(O - 1) div 12, ((O - 1) rem 12) + 1}.

current_month() ->
    {{Y, M, _}, _} = calendar:now_to_datetime(erlang:timestamp()),
    {Y, M}.

pname({Y, M}) ->
    lists:flatten(io_lib:format("query_log_~4..0B_~2..0B", [Y, M])).

create_partition({Y, M}) ->
    {NY, NM} = unord(ord({Y, M}) + 1),
    pq(lists:flatten(io_lib:format(
        "CREATE TABLE ~s PARTITION OF query_log "
        "FOR VALUES FROM ('~4..0B-~2..0B-01') TO ('~4..0B-~2..0B-01')",
        [pname({Y, M}), Y, M, NY, NM]))).

set_retention(V) when is_integer(V) -> set_retention(integer_to_list(V));
set_retention(V) ->
    pq("INSERT INTO settings (key, value) VALUES ('query_log_retention_months', '"
       ++ V ++ "') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value").

%% Real children of query_log in the scratch schema only, sorted.
partitions() ->
    {ok, _, Rows} = pq(
        "SELECT c.relname FROM pg_inherits i "
        "JOIN pg_class c ON c.oid = i.inhrelid "
        "JOIN pg_class p ON p.oid = i.inhparent "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE p.relname = 'query_log' AND n.nspname = '" ?SCHEMA "'"),
    lists:sort([binary_to_list(N) || {N} <- Rows]).

table_exists(Name) ->
    {ok, _, [{Exists}]} = pq(
        "SELECT EXISTS (SELECT 1 FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = '" ?SCHEMA "' AND c.relname = '" ++ Name ++ "')"),
    Exists =:= <<"t">>.

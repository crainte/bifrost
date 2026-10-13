%% Common Test suite for bifrost_migrations against a REAL Postgres. Every test
%% here is the regression for a bug that shipped:
%%
%%  1. applied_migrations_are_not_reapplied — squery uses the TEXT protocol, so
%%     "SELECT version" returns <<"1">>, while extract_version/1 returns 1.
%%     lists:member(1, [<<"1">>]) is always false, so EVERY migration re-ran on
%%     EVERY boot. Fixed by binary_to_integer/1 in get_applied_versions/1.
%%  2. concurrent_runners_apply_each_migration_once — all replicas run migrations
%%     on boot at the same time with nothing serializing them. Fixed with a
%%     session-level pg_advisory_lock(3405691582) held across the whole run.
%%  3. failed_migration_rolls_back_and_records_nothing — the migration SQL and
%%     its schema_migrations INSERT were separate statements, so a failure
%%     between them left the DDL committed and unrecorded, replaying it forever.
%%     Fixed with explicit BEGIN/COMMIT (ROLLBACK on failure) in
%%     apply_migration/4, and a hard error when the record fails.
%%  4. migration_record_uses_bound_parameters — record_migration/3 built its
%%     INSERT by string interpolation. Fixed with epgsql:equery/3 and $1/$2.
%%  5. rdap_cache_backfill_unfreezes_age_and_retries_unknowns — rdap_cache stored
%%     age_days as of the lookup, so ages never advanced, and stored every failure
%%     as a permanent all-NULL row. Migration 014 must recover registered_on from
%%     existing rows and turn unclassifiable negatives into one due retry.
%%
%% Requires a reachable Postgres. Connection is taken from env so the same suite
%% runs in CI/dev:
%%   BIFROST_TEST_DB_HOST (default "postgres"), BIFROST_TEST_DB_PORT (5432),
%%   BIFROST_TEST_DB_NAME (bifrost), BIFROST_TEST_DB_USER (bifrost),
%%   BIFROST_TEST_DB_PASSWORD (bifrost).
%%
%% ISOLATION: the target database is the live dev DB. Every connection this
%% suite opens immediately does SET search_path TO <scratch schema>, and the
%% migrations use unqualified table names, so all of it (schema_migrations
%% included) lands in throwaway schemas that end_per_suite drops. The advisory
%% lock is cluster-global rather than schema-scoped — that is precisely what
%% test 2 exercises.
-module(bifrost_migrations_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([applied_migrations_are_not_reapplied/1,
         concurrent_runners_apply_each_migration_once/1,
         failed_migration_rolls_back_and_records_nothing/1,
         migration_record_uses_bound_parameters/1,
         rdap_cache_backfill_unfreezes_age_and_retries_unknowns/1]).

-define(RUNNERS, 4).

all() ->
    [applied_migrations_are_not_reapplied,
     concurrent_runners_apply_each_migration_once,
     failed_migration_rolls_back_and_records_nothing,
     migration_record_uses_bound_parameters,
     rdap_cache_backfill_unfreezes_age_and_retries_unknowns].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(epgsql),
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    %% Unique per run so a crashed previous run cannot collide with this one.
    Prefix = "ct_mig_" ++ integer_to_list(erlang:system_time(millisecond)),
    %% Fail loudly rather than silently testing an empty migration set.
    Files = real_migration_files(),
    ?assertNotEqual([], Files),
    [{db, Db}, {schema_prefix, Prefix}, {migration_count, length(Files)} | Config].

end_per_suite(Config) ->
    C = raw_connect(Config),
    Prefix = ?config(schema_prefix, Config),
    {ok, _, Rows} = epgsql:equery(
        C, "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE $1",
        [list_to_binary(Prefix ++ "%")]),
    [sq(C, "DROP SCHEMA " ++ binary_to_list(S) ++ " CASCADE") || {S} <- Rows],
    ok = epgsql:close(C),
    ok.

%% ── 1: checkpointing ──────────────────────────────────────────
%% Two runs on the same connection must leave the bookkeeping untouched. The
%% applied_at timestamps are the real assertion: identical to the byte means
%% nothing was re-applied. With binary_to_integer/1 removed, the second run
%% re-applies everything and blows up on the duplicate-key record instead.
applied_migrations_are_not_reapplied(Config) ->
    C = connect(Config, new_schema(Config, "reapply")),
    ok = bifrost_migrations:run(C),
    First = rows(C, "SELECT version, applied_at, filename FROM schema_migrations"
                    " ORDER BY version"),
    ?assertEqual(?config(migration_count, Config), length(First)),
    ok = bifrost_migrations:run(C),
    Second = rows(C, "SELECT version, applied_at, filename FROM schema_migrations"
                     " ORDER BY version"),
    ?assertEqual(First, Second),
    ok = epgsql:close(C).

%% ── 2: serialization ──────────────────────────────────────────
%% Four connections starting from an empty schema, released simultaneously.
%% Without the advisory lock they all read an empty applied-set and race to
%% apply migration 001.
concurrent_runners_apply_each_migration_once(Config) ->
    Schema = new_schema(Config, "race"),
    C0 = connect(Config, Schema),
    %% Pre-create the bookkeeping table: ensure_schema_table/1 runs BEFORE the
    %% lock is taken, and concurrent CREATE TABLE IF NOT EXISTS is a known
    %% Postgres race that has nothing to do with the bug under test.
    sq(C0, "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY,"
           " applied_at TIMESTAMPTZ NOT NULL DEFAULT now(), filename TEXT NOT NULL)"),
    Conns = [connect(Config, Schema) || _ <- lists:seq(1, ?RUNNERS)],
    Runners = [spawn_monitor(fun() ->
                   receive go -> ok end,
                   bifrost_migrations:run(C)
               end) || C <- Conns],
    [Pid ! go || {Pid, _} <- Runners],
    Reasons = [receive {'DOWN', Ref, process, _, Why} -> Why
               after 60000 -> timeout end || {_, Ref} <- Runners],
    ?assertEqual(lists:duplicate(?RUNNERS, normal), Reasons),

    Counts = rows(C0, "SELECT version, count(*) FROM schema_migrations"
                      " GROUP BY version ORDER BY version"),
    ?assertEqual([], [R || {_, N} = R <- Counts, N =/= <<"1">>]),
    %% Guards against discovery silently finding nothing.
    ?assertEqual(?config(migration_count, Config), length(Counts)),
    [ok = epgsql:close(C) || C <- [C0 | Conns]],
    ok.

%% ── 3: atomicity ──────────────────────────────────────────────
%% Two ways a migration can fail, both of which must leave the database exactly
%% as it was.
%%
%% Phase B is the one that pins the explicit BEGIN/COMMIT down: Postgres already
%% wraps a multi-statement simple query in an implicit transaction, so a
%% syntactically broken file rolls back on its own and proves nothing about
%% apply_migration/4's transaction. The gap bug 3 was about is between the
%% migration SQL and the separate record_migration/3 statement, so we make the
%% RECORD fail (a CHECK constraint on filename) after the migration SQL
%% succeeded. Without BEGIN/COMMIT the probe table stays committed.
failed_migration_rolls_back_and_records_nothing(Config) ->
    C = connect(Config, new_schema(Config, "rollback")),
    sq(C, "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY,"
          " applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
          " filename TEXT NOT NULL CHECK (filename <> '900_probe.sql'))"),

    %% Phase A: the migration SQL itself is invalid.
    with_migration_dir(Config, "broken",
        [{"901_broken.sql", <<"CREATE TABLE ct_rollback_probe (id INT);\n"
                              "THIS IS NOT SQL;\n">>}],
        fun() -> ?assertError({migration_failed, _, _}, bifrost_migrations:run(C)) end),

    %% Phase B: the migration SQL succeeds, recording it does not.
    with_migration_dir(Config, "unrecordable",
        [{"900_probe.sql", <<"CREATE TABLE ct_rollback_probe (id INT);\n">>}],
        fun() -> ?assertError({migration_record_failed, _, _}, bifrost_migrations:run(C)) end),

    %% run/1 never reached COMMIT, so this connection is still inside the
    %% aborted transaction — closing it out is what makes the DDL disappear.
    epgsql:squery(C, "ROLLBACK"),
    ?assertEqual([{<<"t">>}], rows(C, "SELECT to_regclass('ct_rollback_probe') IS NULL")),
    ?assertEqual([], rows(C, "SELECT version FROM schema_migrations")),
    ok = epgsql:close(C).

%% ── 4: bound parameters ───────────────────────────────────────
%% Driven through the real public path: a migration whose FILENAME contains a
%% single quote. String-interpolating that into the INSERT produces a syntax
%% error, so run/1 would raise {migration_record_failed, ...} instead of
%% round-tripping the name.
migration_record_uses_bound_parameters(Config) ->
    C = connect(Config, new_schema(Config, "quote")),
    Name = "910_o'brien.sql",
    with_migration_dir(Config, "quote",
        [{Name, <<"CREATE TABLE ct_quote_probe (id INT);\n">>}],
        fun() -> ok = bifrost_migrations:run(C) end),
    ?assertEqual([{910, list_to_binary(Name)}],
                 [{binary_to_integer(V), F} ||
                     {V, F} <- rows(C, "SELECT version, filename FROM schema_migrations")]),
    ok = epgsql:close(C).

%% ── 5: rdap_cache backfill (014) ──────────────────────────────
%% Rows written by the previous release, migrated in place. Runs the REAL
%% migration files: everything before 014 first, then seeds old-shape rows, then
%% 014 on its own, exactly as an upgraded pod would see it.
rdap_cache_backfill_unfreezes_age_and_retries_unknowns(Config) ->
    C = connect(Config, new_schema(Config, "rdap014")),
    RealDir = filename:join(code:priv_dir(bifrost), "migrations"),
    {Before, [Target]} = lists:partition(
        fun(F) -> F < "014" end,
        [F || F <- lists:sort(real_migration_files()), F < "015"]),
    ?assertEqual("014_rdap_cache_status.sql", Target),
    Read = fun(F) -> {ok, B} = file:read_file(filename:join(RealDir, F)), {F, B} end,
    with_migration_dir(Config, "rdap014", [Read(F) || F <- Before],
                       fun() -> ok = bifrost_migrations:run(C) end),

    %% Looked up 30 days ago when it was 10 days old: registered 40 days ago.
    sq(C, "INSERT INTO rdap_cache (domain, age_days, has_transfer_lock, pending_delete,"
          " privacy_protected, looked_up) VALUES"
          " ('aged.example', 10, false, false, true, now() - interval '30 days'),"
          " ('negative.example', NULL, NULL, NULL, NULL, now() - interval '30 days'),"
          " ('flags.example', NULL, true, false, false, now())"),

    with_migration_dir(Config, "rdap014", [Read(Target)],
                       fun() -> ok = bifrost_migrations:run(C) end),

    ?assertEqual([{<<"aged.example">>, <<"ok">>, <<"40">>, <<"0">>, <<"t">>},
                  {<<"flags.example">>, <<"ok">>, null, <<"0">>, <<"t">>},
                  {<<"negative.example">>, <<"transient">>, null, <<"0">>, <<"f">>}],
                 rows(C, "SELECT domain, status, (current_date - registered_on)::text,"
                         " attempts::text, retry_at IS NULL"
                         " FROM rdap_cache ORDER BY domain")),
    %% The negative row is due NOW, not at some later backoff.
    ?assertEqual([{<<"t">>}],
                 rows(C, "SELECT retry_at <= now() FROM rdap_cache"
                         " WHERE domain = 'negative.example'")),
    %% The CHECK constraint is in place.
    ?assertMatch({error, _}, epgsql:squery(C, "UPDATE rdap_cache SET status = 'bogus'")),
    ok = epgsql:close(C).

%% ── helpers ───────────────────────────────────────────────────

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

raw_connect(Config) ->
    #{host := H, port := P, name := D, user := U, pass := PW} = ?config(db, Config),
    {ok, C} = epgsql:connect(H, U, PW, [{port, P}, {database, D}, {timeout, 5000}]),
    C.

%% search_path is per-connection, so every connection goes through here.
connect(Config, Schema) ->
    C = raw_connect(Config),
    sq(C, "SET search_path TO " ++ Schema),
    C.

new_schema(Config, Tag) ->
    Schema = ?config(schema_prefix, Config) ++ "_" ++ Tag,
    C = raw_connect(Config),
    sq(C, "CREATE SCHEMA " ++ Schema),
    ok = epgsql:close(C),
    Schema.

sq(C, Sql) ->
    case epgsql:squery(C, Sql) of
        {ok, _} = R -> R;
        {ok, _, _} = R -> R;
        Other -> ct:fail({sql_failed, Sql, Other})
    end.

rows(C, Sql) ->
    {ok, _, Rows} = sq(C, Sql),
    Rows.

%% bifrost_migrations:migration_dir/0 resolves through code:priv_dir(bifrost),
%% which resolves the app from the code path — so prepending a fake
%% <tmp>/<tag>/bifrost/ebin redirects it to <tmp>/<tag>/bifrost/priv/migrations.
%% Files :: [{Name, Contents}]. Restored on the way out.
with_migration_dir(Config, Tag, Files, Fun) ->
    App = filename:join([?config(priv_dir, Config), Tag, "bifrost"]),
    Ebin = filename:join(App, "ebin"),
    Dir = filename:join([App, "priv", "migrations"]),
    ok = filelib:ensure_dir(filename:join(Ebin, ".keep")),
    ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
    [ok = file:write_file(filename:join(Dir, N), Body) || {N, Body} <- Files],
    true = code:add_patha(Ebin),
    try
        %% If this ever stops holding, the test would silently run the REAL
        %% migrations instead of the fixtures.
        ?assertEqual(Dir, filename:join(code:priv_dir(bifrost), "migrations")),
        Fun()
    after
        code:del_path(Ebin)
    end.

real_migration_files() ->
    Dir = filename:join(code:priv_dir(bifrost), "migrations"),
    {ok, Files} = file:list_dir(Dir),
    [F || F <- Files, re:run(F, "^[0-9]+.*\\.sql$", [{capture, none}]) =:= match].

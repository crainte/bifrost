-module(bifrost_migrations).

-export([run/1]).

%% Run all pending migrations from priv/migrations/
%% Takes the epgsql connection directly to avoid calling back through GenServer
run(Conn) ->
    ensure_schema_table(Conn),
    %% ponytail: every pod runs migrations on boot; one session advisory lock
    %% serializes them. Released automatically if the connection dies.
    {ok, _, _} = epgsql:squery(Conn, "SELECT pg_advisory_lock(3405691582)"),
    try
        run_pending(Conn)
    after
        epgsql:squery(Conn, "SELECT pg_advisory_unlock(3405691582)")
    end.

run_pending(Conn) ->
    Applied = get_applied_versions(Conn),
    MigrationDir = migration_dir(),
    case file:list_dir(MigrationDir) of
        {ok, Files} ->
            Migrations = lists:sort([F || F <- Files, is_migration(F)]),
            lists:foreach(fun(F) ->
                Version = extract_version(F),
                case lists:member(Version, Applied) of
                    true -> ok;
                    false -> apply_migration(Conn, MigrationDir, F, Version)
                end
            end, Migrations),
            ok;
        {error, Reason} ->
            logger:warning("could not list migrations dir ~s: ~p", [MigrationDir, Reason]),
            ok
    end.

ensure_schema_table(Conn) ->
    Sql = "CREATE TABLE IF NOT EXISTS schema_migrations ("
          "version INTEGER PRIMARY KEY, "
          "applied_at TIMESTAMPTZ NOT NULL DEFAULT now(), "
          "filename TEXT NOT NULL)",
    case epgsql:squery(Conn, Sql) of
        {ok, _} -> ok;
        {ok, _, _} -> ok;
        {error, E} -> logger:error("failed to create schema_migrations: ~p", [E])
    end.

get_applied_versions(Conn) ->
    %% squery uses the text protocol: INTEGER comes back as a binary.
    case epgsql:squery(Conn, "SELECT version FROM schema_migrations ORDER BY version") of
        {ok, _, Rows} -> [binary_to_integer(V) || {V} <- Rows];
        _ -> []
    end.

migration_dir() ->
    case code:priv_dir(bifrost) of
        {error, _} -> "priv/migrations";
        Dir -> filename:join(Dir, "migrations")
    end.

is_migration(Filename) ->
    case re:run(Filename, "^[0-9]+.*\\.sql$", [{capture, none}]) of
        match -> true;
        _ -> false
    end.

extract_version(Filename) ->
    case re:run(Filename, "^([0-9]+)", [{capture, [1], list}]) of
        {match, [V]} -> list_to_integer(V);
        _ -> 0
    end.

apply_migration(Conn, Dir, Filename, Version) ->
    Path = filename:join(Dir, Filename),
    case file:read_file(Path) of
        {ok, Sql} ->
            logger:info("applying migration ~s", [Filename]),
            %% Migration and its bookkeeping row commit together or not at all.
            epgsql:squery(Conn, "BEGIN"),
            Results = epgsql:squery(Conn, binary_to_list(Sql)),
            case all_ok(Results) of
                true ->
                    record_migration(Conn, Version, Filename),
                    epgsql:squery(Conn, "COMMIT"),
                    logger:info("migration ~s applied", [Filename]);
                false ->
                    epgsql:squery(Conn, "ROLLBACK"),
                    logger:error("migration ~s failed: ~p", [Filename, Results]),
                    error({migration_failed, Filename, Results})
            end;
        {error, E} ->
            logger:error("could not read migration ~s: ~p", [Path, E]),
            error({migration_read_failed, Path, E})
    end.

all_ok(Results) when is_list(Results) -> lists:all(fun all_ok/1, Results);
all_ok({ok, _}) -> true;
all_ok({ok, _, _}) -> true;
all_ok(_) -> false.

record_migration(Conn, Version, Filename) ->
    Sql = "INSERT INTO schema_migrations (version, filename) VALUES ($1, $2)",
    case epgsql:equery(Conn, Sql, [Version, list_to_binary(Filename)]) of
        {ok, _} -> ok;
        {error, E} -> error({migration_record_failed, Filename, E})
    end.

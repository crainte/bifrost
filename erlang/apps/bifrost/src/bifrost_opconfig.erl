%% Last-known operational config, so DNS keeps its rewrites, allowlist and
%% blocks when Postgres is down or hung.
%%
%% Postgres stays the source of truth. Every successful read is snapshotted
%% into the replicated `opconfig` Mnesia table (disc_copies, so it also survives
%% a full cluster restart); a failed or timed-out read is answered from that
%% snapshot instead. Without it, a pod that (re)hydrated during a Postgres outage
%% came up with no rewrites (`nas.home` stopped resolving), no allowlist
%% (allowed domains were blocked again) and none of the UI-added blocklists.
-module(bifrost_opconfig).

-export([read/2, snapshot/1, store/2]).

-record(opconfig, {key :: atom(), value :: term()}).

%% Bound on one hydration-time read. A hung Postgres costs this, then the
%% snapshot is used.
-define(DB_TIMEOUT, 3000).

%% Run `Sql` and transform its rows with `Fun`. Returns {ok, Value} from
%% Postgres (and refreshes the snapshot), {ok, Value} from the snapshot when
%% Postgres fails, or `error` when neither is available.
-spec read(atom(), {string(), fun((list()) -> term())}) -> {ok, term()} | error.
read(Key, {Sql, Fun}) ->
    case bifrost_db_pool:query(Sql, ?DB_TIMEOUT) of
        {ok, _, Rows} when is_list(Rows) ->
            Value = Fun(Rows),
            store(Key, Value),
            {ok, Value};
        Other ->
            logger:warning("operational config ~p unavailable from Postgres (~p), "
                           "using last-known snapshot", [Key, Other]),
            snapshot(Key)
    end.

-spec snapshot(atom()) -> {ok, term()} | error.
snapshot(Key) ->
    try mnesia:dirty_read(opconfig, Key) of
        [#opconfig{value = V}] -> {ok, V};
        [] -> error
    catch _:_ -> error
    end.

%% Writes only on change: every node re-reads on every config broadcast, and an
%% unchanged value must not generate a cluster-wide replication + table event.
-spec store(atom(), term()) -> ok.
store(Key, Value) ->
    case snapshot(Key) of
        {ok, Value} -> ok;
        _ ->
            try mnesia:dirty_write(#opconfig{key = Key, value = Value})
            catch C:R -> logger:warning("opconfig snapshot write failed: ~p:~p", [C, R])
            end,
            ok
    end.

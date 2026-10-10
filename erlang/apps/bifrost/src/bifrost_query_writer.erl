-module(bifrost_query_writer).
-behaviour(gen_server).

%% Buffers query events from Rust and writes them to query_log in batches.
%%
%%  - Its own connection (bifrost_db_writer): per-query logging never queues
%%    behind a slow dashboard scan on the shared pool, and never delays it.
%%  - Multi-row INSERTs: one round trip per ?BATCH_ROWS events instead of one
%%    per event. If Postgres rejects a batch (a malformed event), that batch is
%%    retried row by row so one bad event cannot drop its neighbours.
%%  - Bounded: while Postgres is unreachable events stay buffered (and are
%%    written once it returns) up to ?MAX_BUFFER; beyond that new events are
%%    counted and dropped rather than growing the heap without limit.
%%  - The outage is logged once (then at most every ?WARN_EVERY_MS), not once
%%    per query.

-export([start_link/0, max_buffer/0, stats/0]).
%% Exported for the retention test suite, which drives the real partition
%% upkeep against a real Postgres and must call the pruning path directly for a
%% fixed reference month rather than waiting for a month to roll over.
-export([maintain_partitions/1, drop_expired_partitions/2, retention_months/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(POOL, bifrost_db_writer).
-define(FLUSH_INTERVAL, 500).
-define(FLUSH_THRESHOLD, 500).
-define(BATCH_ROWS, 500).
-define(MAX_BUFFER, 20000).
-define(INSERT_TIMEOUT, 10000).
-define(WARN_EVERY_MS, 60000).
%% Fallback when the settings row is missing. 0 would mean "keep forever".
-define(DEFAULT_RETENTION_MONTHS, 6).

-record(state, {
    %% Newest first; `count` tracks its length so nothing is O(n) per event.
    buffer = [] :: list(),
    count = 0 :: non_neg_integer(),
    dropped = 0 :: non_neg_integer(),
    %% Monotonic ms of the last outage warning; undefined = not in an outage.
    outage_warned :: integer() | undefined,
    %% {Year, Month} the partitions were last maintained for. Partition upkeep
    %% is month-granular, so doing it on every flush (twice per 500ms) was pure
    %% waste; this collapses it to once per month per node.
    ensured :: {integer(), integer()} | undefined
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

max_buffer() -> ?MAX_BUFFER.

%% Observability (and tests): events waiting to be written, and events dropped
%% because the buffer was full during an outage.
stats() ->
    gen_server:call(?MODULE, stats).

init([]) ->
    logger:info("~s started", [?MODULE]),
    erlang:send_after(?FLUSH_INTERVAL, self(), flush),
    {ok, #state{}}.

handle_call(stats, _From, State = #state{count = C, dropped = D}) ->
    {reply, #{buffered => C, dropped => D}, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({query_event, _Event}, State = #state{count = C, dropped = D}) when C >= ?MAX_BUFFER ->
    {noreply, State#state{dropped = D + 1}};
handle_cast({query_event, Event}, State = #state{buffer = Buf, count = C, outage_warned = Out}) ->
    NewState = State#state{buffer = [Event | Buf], count = C + 1},
    %% Early flush only while Postgres is reachable. During an outage the buffer
    %% stays above the threshold, and retrying on every event would make each
    %% one cost a pass over the whole buffer; the timer retries instead.
    case C + 1 >= ?FLUSH_THRESHOLD andalso Out =:= undefined of
        true -> {noreply, flush(NewState)};
        false -> {noreply, NewState}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(flush, State) ->
    NewState = flush(State),
    erlang:send_after(?FLUSH_INTERVAL, self(), flush),
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

flush(State = #state{count = 0}) ->
    State;
flush(State = #state{buffer = Buf, ensured = Ensured}) ->
    NewEnsured = maintain_partitions(Ensured),
    case write(lists:reverse(Buf)) of
        ok ->
            recovered(State#state{buffer = [], count = 0, ensured = NewEnsured});
        {unavailable, Unwritten, Reason} ->
            %% Keep what was not written (oldest first) for the next flush.
            outage(Reason, State#state{buffer = lists:reverse(Unwritten),
                                       count = length(Unwritten), ensured = NewEnsured})
    end.

%% Writes oldest-first in batches. Stops at the first sign Postgres is
%% unavailable and hands back everything not yet written.
write([]) ->
    ok;
write(Events) ->
    {Batch, Rest} = take(?BATCH_ROWS, Events, []),
    Rows = [R || E <- Batch, {ok, R} <- [row(E)]],
    case insert(Rows) of
        ok -> write(Rest);
        {rejected, _} -> insert_one_by_one(Rows), write(Rest);
        {unavailable, Reason} -> {unavailable, Events, Reason}
    end.

insert([]) ->
    ok;
insert(Rows) ->
    {Sql, Params} = insert_sql(Rows),
    case bifrost_db_pool:pool_equery(?POOL, Sql, Params, ?INSERT_TIMEOUT) of
        {ok, _} -> ok;
        {error, E} when is_tuple(E), tuple_size(E) =:= 6, element(1, E) =:= error ->
            {rejected, E};
        {error, Reason} ->
            {unavailable, Reason}
    end.

%% Only reached after Postgres rejected a batch: isolate the bad row(s).
insert_one_by_one(Rows) ->
    lists:foreach(fun(R) ->
        case insert([R]) of
            ok -> ok;
            {_, Reason} -> logger:warning("dropping query event Postgres rejected: ~p", [Reason])
        end
    end, Rows).

-define(COLS, 10).

insert_sql(Rows) ->
    Values = lists:join(",", [placeholders(I) || I <- lists:seq(0, length(Rows) - 1)]),
    Sql = ["INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode, ede_code, "
           "list_id, latency_us, queried_at, response_records) VALUES ", Values],
    {lists:flatten(Sql), lists:append(Rows)}.

placeholders(I) ->
    B = I * ?COLS,
    P = fun(N) -> "$" ++ integer_to_list(B + N) end,
    lists:flatten(["(", P(1), ",", P(2), ",", P(3), ",", P(4), "::rcode_type,", P(5),
                   "::rcode_type,", P(6), ",", P(7), ",", P(8), ",to_timestamp(", P(9), "),",
                   P(10), "::jsonb)"]).

row(E) when is_map(E) ->
    ClientIp = case maps:get(<<"client_ip">>, E, null) of
        IPBin when is_binary(IPBin) ->
            case inet:parse_address(binary_to_list(IPBin)) of
                {ok, IP} -> IP;
                _ -> null
            end;
        _ -> null
    end,
    QueriedAt = case maps:get(<<"queried_at">>, E, null) of
        V when is_integer(V) -> V;
        _ -> erlang:system_time(second)
    end,
    Records = case maps:get(<<"response_records">>, E, null) of
        Rs when is_list(Rs), Rs =/= [] -> jsx:encode(Rs);
        _ -> null
    end,
    {ok, [ClientIp, maps:get(<<"domain">>, E, null), maps:get(<<"qtype">>, E, null),
          maps:get(<<"action">>, E, null), maps:get(<<"client_rcode">>, E, null),
          maps:get(<<"ede_code">>, E, null), maps:get(<<"list_id">>, E, null),
          maps:get(<<"latency_us">>, E, null), QueriedAt, Records]};
row(_) ->
    skip.

take(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
take(_, [], Acc) -> {lists:reverse(Acc), []};
take(N, [H | T], Acc) -> take(N - 1, T, [H | Acc]).

outage(Reason, State = #state{outage_warned = Last, count = C, dropped = D}) ->
    Now = erlang:monotonic_time(millisecond),
    case Last =:= undefined orelse Now - Last >= ?WARN_EVERY_MS of
        true ->
            logger:warning("query_log unavailable (~p): ~p events buffered, ~p dropped",
                           [Reason, C, D]),
            State#state{outage_warned = Now};
        false ->
            State
    end.

recovered(State = #state{outage_warned = undefined}) ->
    State;
recovered(State = #state{dropped = D}) ->
    logger:info("query_log writes recovered (~p events were dropped during the outage)", [D]),
    State#state{outage_warned = undefined, dropped = 0}.

%% Create the current + next month partitions, then drop expired ones. Returns
%% the month it maintained so the caller can skip until the month rolls over —
%% but ONLY once both partitions exist. A pod that boots while Postgres is down
%% used to record the month as done anyway, and every event that month then
%% landed in a missing partition and was dropped.
maintain_partitions(Ensured) ->
    {{Year, Month, _}, _} = calendar:now_to_datetime(erlang:timestamp()),
    case Ensured of
        {Year, Month} ->
            Ensured;
        _ ->
            {NextY, NextM} = next_month(Year, Month),
            case {ensure_partition(Year, Month), ensure_partition(NextY, NextM)} of
                {ok, ok} ->
                    drop_expired_partitions(Year, Month),
                    {Year, Month};
                _ ->
                    Ensured
            end
    end.

next_month(Year, 12) -> {Year + 1, 1};
next_month(Year, Month) -> {Year, Month + 1}.

%% ── Retention ────────────────────────────────────────────────
%% query_log is the only table that grows without bound (~160 bytes/row with
%% indexes, so ~0.5GB/month at 100k queries/day). Partitioning already makes
%% deletion free — a DROP TABLE is instant and needs no VACUUM — but nothing
%% ever dropped anything, so the database grew forever.
%%
%% Retention is in whole months and read from the settings table at each
%% rollover, so an operator can change it live. 0 disables dropping entirely.
drop_expired_partitions(Year, Month) ->
    case retention_months() of
        0 ->
            ok;
        Keep ->
            %% Months are compared as an absolute ordinal, so year boundaries
            %% need no special casing. Cutoff is the oldest month we keep.
            Cutoff = Year * 12 + Month - Keep,
            lists:foreach(
                fun({Name, PYear, PMonth}) ->
                    case PYear * 12 + PMonth < Cutoff of
                        true -> drop_partition(Name);
                        false -> ok
                    end
                end, existing_partitions())
    end.

%% Enumerate REAL partitions of query_log via pg_inherits rather than globbing
%% table names, so nothing outside the partition set can ever be selected for
%% dropping. The regex then pins the name to exactly query_log_YYYY_MM, which is
%% also what makes it safe to interpolate into the DROP below.
existing_partitions() ->
    Sql = "SELECT c.relname FROM pg_inherits i "
          "JOIN pg_class c ON c.oid = i.inhrelid "
          "JOIN pg_class p ON p.oid = i.inhparent "
          "WHERE p.relname = 'query_log'",
    case bifrost_db_pool:query(Sql) of
        {ok, _, Rows} ->
            lists:filtermap(fun({Name}) -> parse_partition(Name) end, Rows);
        _ ->
            []
    end.

parse_partition(Name) ->
    case re:run(Name, "^query_log_([0-9]{4})_([0-9]{2})$", [{capture, [1, 2], list}]) of
        {match, [Y, M]} -> {true, {Name, list_to_integer(Y), list_to_integer(M)}};
        nomatch -> false
    end.

drop_partition(Name) ->
    %% IF EXISTS because every node's writer runs this at the same rollover; a
    %% peer may have dropped it microseconds earlier.
    Sql = "DROP TABLE IF EXISTS " ++ binary_to_list(Name),
    case bifrost_db_pool:query(Sql) of
        {ok, _, _} -> logger:info("dropped expired query_log partition ~s", [Name]);
        {ok, _} -> logger:info("dropped expired query_log partition ~s", [Name]);
        {error, Reason} ->
            logger:warning("could not drop partition ~s: ~p", [Name, Reason])
    end.

retention_months() ->
    case bifrost_db_pool:query(
           "SELECT value FROM settings WHERE key = 'query_log_retention_months'") of
        {ok, _, [{Value}]} ->
            try binary_to_integer(Value)
            catch _:_ -> ?DEFAULT_RETENTION_MONTHS
            end;
        _ ->
            ?DEFAULT_RETENTION_MONTHS
    end.

ensure_partition(Year, Month) ->
    Suffix = io_lib:format("~4..0B_~2..0B", [Year, Month]),
    Name = list_to_binary(io_lib:format("query_log_~s", [Suffix])),
    FromDate = io_lib:format("~4..0B-~2..0B-01", [Year, Month]),
    ToDate = case Month of
        12 -> io_lib:format("~4..0B-01-01", [Year + 1]);
        _ -> io_lib:format("~4..0B-~2..0B-01", [Year, Month + 1])
    end,
    Sql = lists:flatten(io_lib:format(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = '~s') THEN "
        "CREATE TABLE ~s PARTITION OF query_log "
        "FOR VALUES FROM ('~s') TO ('~s'); "
        "END IF; END $$;",
        [Name, Name, FromDate, ToDate])),
    case bifrost_db_pool:query(Sql) of
        {ok, _, _} -> ok;
        {ok, _} -> ok;
        {error, Reason} when is_tuple(Reason), tuple_size(Reason) =:= 6 ->
            %% Postgres rejected the DDL: a real problem, say so.
            logger:warning("partition creation for ~s failed: ~p", [Name, Reason]),
            {error, Reason};
        {error, Reason} ->
            %% Unreachable: the writer's own outage warning already reports it,
            %% and this is retried on the next flush.
            {error, Reason}
    end.
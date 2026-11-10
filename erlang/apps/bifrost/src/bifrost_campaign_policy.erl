-module(bifrost_campaign_policy).
-behaviour(gen_server).

%% Distributes the campaign-block rule set to every node's Rust and tracks, per
%% node, whether Rust has really APPLIED it.
%%
%% Postgres (bifrost_campaign_block_store) is the source of truth. A snapshot
%% {revision, rules} is published into the replicated `opconfig` Mnesia table
%% (disc_copies), which is both the cluster bus and the last-known copy for a
%% cold start while Postgres is down. Every node subscribes, adopts a NEWER
%% revision and pushes the FULL set to its own Rust as `apply_campaign_blocks`,
%% which Rust acknowledges by revision (`campaign_blocks_applied` / `_rejected`).
%% Same shape as bifrost_dns_settings_server, with its own revision counter.
%%
%% A rule is only reported enforced once the ack for its revision arrived: an
%% older Rust that does not know the message never acks, so the node stays
%% `applying`/`failed` instead of claiming protection it cannot give.
%%
%% Fail closed: if neither Postgres nor a snapshot can supply the policy,
%% apply_current/0 returns {error, policy_unavailable}. Hydration then does not
%% send reload_complete, so a node never starts serving with an unknown (possibly
%% non-empty) rule set silently treated as empty. An empty policy that WAS read
%% (revision 0, no rules) hydrates normally.

-export([start_link/0, publish/1, refresh/0, sync/0, apply_current/0, handle_ack/2,
         status/0, cluster_status/0, rule_state/2, admission_status/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(KEY, campaign_blocks).
-define(RECONCILE_MS, 30000).
-define(RETRY_MS, 5000).
-define(ACK_TIMEOUT, 5000).

-record(state, {desired, applied, pending, retry, last_error}).

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Write a snapshot into the replicated table unless a newer-or-equal revision
%% is already there. Subscribers on every node adopt it.
publish(Snapshot) ->
    case valid_snapshot(Snapshot) of
        false -> {error, invalid_snapshot};
        true ->
            Revision = maps:get(revision, Snapshot),
            F = fun() ->
                case mnesia:read(opconfig, ?KEY, write) of
                    [{opconfig, ?KEY, #{revision := Existing}}] when Existing >= Revision -> stale;
                    _ -> mnesia:write({opconfig, ?KEY, Snapshot})
                end
            end,
            case mnesia:transaction(F) of
                {atomic, ok} -> ok;
                {atomic, stale} -> {error, stale};
                {aborted, Reason} -> {error, {publication_failed, Reason}}
            end
    end.

%% Re-read Postgres, publish and apply locally. Called after every rule write.
refresh() -> gen_server:call(?MODULE, refresh, 4000).

%% Async refresh+push: a peer's config broadcast or a partition heal.
sync() -> gen_server:cast(?MODULE, sync).

%% Hydration: (re)send the current policy to the freshly connected Rust and wait
%% for its acknowledgement.
apply_current() -> gen_server:call(?MODULE, apply_current, ?ACK_TIMEOUT + 4000).

handle_ack(ConnId, Message) -> gen_server:cast(?MODULE, {ack, ConnId, Message}).

status() -> gen_server:call(?MODULE, status, 1800).

cluster_status() ->
    Durable = try mnesia:system_info(db_nodes) catch _:_ -> [] end,
    Seeds = try bifrost_cluster:seeds() catch _:_ -> [] end,
    %% `nodes()` includes Erlang RPC/observer connections (notably the CT
    %% runner), which are not resolvers and can never ACK this policy. Durable
    %% Mnesia members and configured seeds are the resolver membership; keep
    %% missing seeds in the list so a partition cannot look fully applied.
    Nodes = lists:usort([node() | Durable ++ Seeds]),
    Results = erpc:multicall(Nodes, ?MODULE, status, [], 2000),
    [case R of
         {ok, S} when is_map(S) -> S#{node => N};
         _ -> #{node => N, state => <<"offline">>}
     end || {N, R} <- lists:zip(Nodes, Results)].

%% Never admit a rule while a connected serving resolver has not acknowledged
%% any campaign policy. An API-only node without Rust may still persist intent.
admission_status(Statuses) ->
    case lists:any(fun(S) ->
        maps:get(state, S, undefined) =:= <<"offline">> orelse
        (maps:get(connected, S, false) =:= true andalso
         (maps:get(state, S, undefined) =/= <<"applied">> orelse
          maps:get(applied_revision, S, undefined) =:= undefined))
    end, Statuses) of
        true -> {error, resolver_not_ready};
        false -> ok
    end.

%% Is a rule enforced everywhere? `applied` only if EVERY node reports having
%% applied a revision >= the rule's; an unreachable or failing node keeps it
%% `applying`/`failed`. Pure, so the UI/API logic is unit-testable.
-spec rule_state(non_neg_integer(), [map()]) -> applied | applying | failed.
rule_state(_RuleRevision, []) -> applying;
rule_state(RuleRevision, NodeStatuses) ->
    Behind = [S || S <- NodeStatuses, not covers(S, RuleRevision)],
    case Behind of
        [] -> applied;
        _ -> case lists:any(fun(S) -> maps:get(state, S, undefined) =:= <<"failed">> end, Behind) of
                 true -> failed;
                 false -> applying
             end
    end.

covers(#{applied_revision := A}, R) when is_integer(A) -> A >= R;
covers(_, _) -> false.

init([]) ->
    _ = (catch mnesia:subscribe({table, opconfig, simple})),
    State = case bifrost_opconfig:snapshot(?KEY) of
        {ok, Snapshot} -> case valid_snapshot(Snapshot) of
                              true -> #state{desired = Snapshot};
                              false -> #state{}
                          end;
        error -> #state{}
    end,
    self() ! reconcile,
    {ok, State}.

handle_call(status, _From, State) -> {reply, local_status(State), State};
handle_call(refresh, _From, State) ->
    {Reply, Next} = reconcile_db(State),
    {reply, Reply, Next};
handle_call(apply_current, From, State0) ->
    %% A new connection means a new Rust process: whatever it had applied before
    %% is gone, so stop claiming it.
    {_, State1} = reconcile_db(State0),
    case State1#state.pending of
        {_, _, Waiting, Timer0} -> cancel(Timer0), reply(Waiting, {error, superseded});
        undefined -> ok
    end,
    State = State1#state{applied = undefined, pending = undefined},
    case State#state.desired of
        undefined ->
            %% Neither Postgres nor a snapshot: fail closed.
            {reply, {error, policy_unavailable}, State#state{last_error = <<"policy_unavailable">>}};
        _ ->
            {noreply, send_current(State, From)}
    end;
handle_call(_Request, _From, State) -> {reply, {error, unsupported}, State}.

handle_cast(sync, State) ->
    {_, Next} = reconcile_db(State),
    {noreply, Next};
handle_cast({ack, ConnId, Message}, State = #state{pending = {ConnId, Revision, From, Timer}}) ->
    case Message of
        #{<<"type">> := <<"campaign_blocks_applied">>, <<"revision">> := Revision} ->
            cancel(Timer),
            reply(From, ok),
            {noreply, State#state{pending = undefined, last_error = undefined, retry = undefined,
                                  applied = #{revision => Revision,
                                              at => erlang:system_time(second)}}};
        #{<<"type">> := <<"campaign_blocks_rejected">>, <<"revision">> := Revision} = Rejected ->
            cancel(Timer),
            Error = maps:get(<<"error">>, Rejected, <<"rejected">>),
            reply(From, {error, Error}),
            {noreply, schedule_retry(State#state{pending = undefined, last_error = Error})};
        _ -> {noreply, State}
    end;
handle_cast(_Msg, State) -> {noreply, State}.

handle_info({mnesia_table_event, {write, {opconfig, ?KEY, Snapshot}, _}}, State) ->
    {noreply, adopt(Snapshot, State)};
handle_info(reconcile, State) ->
    {_, Next} = reconcile_db(State),
    erlang:send_after(?RECONCILE_MS, self(), reconcile),
    {noreply, Next};
handle_info({ack_timeout, Ref}, State = #state{pending = {_, _, From, {Ref, _}}}) ->
    reply(From, {error, ack_timeout}),
    {noreply, schedule_retry(State#state{pending = undefined, last_error = <<"ack_timeout">>})};
handle_info(retry_apply, State) ->
    {Result, Next} = reconcile_db(State#state{retry = undefined}),
    case {Result, Next#state.pending} of
        {{error, {publication_failed, _}}, _} -> {noreply, Next};
        {_, undefined} -> {noreply, send_current(Next, undefined)};
        _ -> {noreply, Next}
    end;
handle_info(_Info, State) -> {noreply, State}.

%% Read Postgres; a newer revision is published (so peers and the snapshot get
%% it) and adopted. A failed read leaves the last-known policy in force.
reconcile_db(State) ->
    case bifrost_campaign_block_store:read() of
        {ok, Snapshot} ->
            case newer(Snapshot, State#state.desired) of
                true ->
                    case publish(Snapshot) of
                        ok -> {ok, adopt(Snapshot, State)};
                        {error, stale} -> confirm_publication(Snapshot, State);
                        {error, Reason} -> publication_error(Reason, State)
                    end;
                false -> ensure_snapshot(Snapshot, State)
            end;
        {error, Reason} ->
            logger:warning("campaign block policy unavailable from Postgres: ~p", [Reason]),
            {{error, Reason}, State}
    end.

ensure_snapshot(Snapshot, State = #state{desired = Snapshot}) ->
    case bifrost_opconfig:snapshot(?KEY) of
        {ok, Snapshot} -> {ok, clear_publication_error(State)};
        _ -> case publish(Snapshot) of
                 ok -> {ok, clear_publication_error(State)};
                 {error, Reason} -> publication_error(Reason, State)
             end
    end;
ensure_snapshot(_Snapshot, State) -> {ok, State}.

clear_publication_error(State = #state{last_error = <<"publication_failed">>}) ->
    State#state{last_error = undefined};
clear_publication_error(State) -> State.

confirm_publication(Snapshot, State) ->
    case bifrost_opconfig:snapshot(?KEY) of
        {ok, Snapshot} -> {ok, adopt(Snapshot, State)};
        _ -> publication_error(snapshot_not_confirmed, State)
    end.

publication_error(Reason, State) ->
    logger:error("campaign policy snapshot publication failed: ~p", [Reason]),
    {{error, {publication_failed, Reason}},
     schedule_retry(State#state{last_error = <<"publication_failed">>})}.

newer(#{revision := R}, undefined) when is_integer(R) -> true;
newer(#{revision := R}, #{revision := D}) -> R > D;
newer(_, _) -> false.

adopt(Snapshot, State) ->
    case valid_snapshot(Snapshot) andalso newer(Snapshot, State#state.desired) of
        false -> State;
        true -> send_current(State#state{desired = Snapshot, last_error = undefined}, undefined)
    end.

send_current(State = #state{desired = undefined}, From) ->
    reply(From, {error, policy_unavailable}),
    State;
send_current(State = #state{desired = #{revision := Revision, rules := Rules}}, From) ->
    case catch bifrost_socket_server:connection_id() of
        ConnId when ConnId =/= undefined, not is_tuple(ConnId) ->
            Msg = #{type => <<"apply_campaign_blocks">>, revision => Revision, rules => Rules},
            case catch bifrost_socket_server:send_message(Msg) of
                ok ->
                    Ref = make_ref(),
                    Timer = {Ref, erlang:send_after(?ACK_TIMEOUT, self(), {ack_timeout, Ref})},
                    %% A newer push supersedes an unacknowledged older one. A
                    %% hydration still waiting on the old push keeps waiting,
                    %% now for this (newer) revision's ack.
                    Waiter = case {From, State#state.pending} of
                        {undefined, {_, _, Old, OldRef}} -> cancel(OldRef), Old;
                        {_, {_, _, Old, OldRef}} -> cancel(OldRef), reply(Old, {error, superseded}), From;
                        _ -> From
                    end,
                    State#state{pending = {ConnId, Revision, Waiter, Timer}};
                Error ->
                    reply(From, {error, Error}),
                    schedule_retry(State#state{last_error = <<"send_failed">>})
            end;
        _ ->
            reply(From, {error, not_connected}),
            State
    end.

valid_snapshot(#{revision := R, rules := L}) when is_integer(R), R >= 0, is_list(L) -> true;
valid_snapshot(_) -> false.

local_status(#state{desired = D, applied = A, pending = P, last_error = Err}) ->
    DesiredRev = case D of undefined -> undefined; _ -> maps:get(revision, D) end,
    AppliedRev = case A of undefined -> undefined; _ -> maps:get(revision, A) end,
    Connected = case catch bifrost_socket_server:connection_id() of
                    Id when Id =/= undefined, not is_tuple(Id) -> true;
                    _ -> false
                end,
    #{connected => Connected, desired_revision => DesiredRev,
      applied_revision => AppliedRev,
      state => if
                   P =/= undefined -> <<"applying">>;
                   DesiredRev =/= undefined, DesiredRev =:= AppliedRev -> <<"applied">>;
                   Err =/= undefined -> <<"failed">>;
                   true -> <<"pending">>
               end,
      last_error => Err}.

schedule_retry(State = #state{retry = undefined}) ->
    State#state{retry = erlang:send_after(?RETRY_MS, self(), retry_apply)};
schedule_retry(State) -> State.

cancel({_, TimerRef}) -> erlang:cancel_timer(TimerRef).
reply(undefined, _) -> ok;
reply(From, Reply) -> gen_server:reply(From, Reply).

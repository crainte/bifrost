-module(bifrost_dns_settings_server).
-behaviour(gen_server).

-export([start_link/0, effective/0, status/0, cluster_status/0, publish/1, save/4,
         apply_current/0, handle_ack/2, refresh/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(KEY, dns_settings).
-define(RECONCILE_MS, 30000).
-define(ACK_TIMEOUT, 5000).
-define(SECTIONS, [<<"upstreams">>, <<"routes">>, <<"cache">>, <<"blocking">>,
                   <<"reverse_dns">>]).

-record(state, {desired, effective, applied, pending, retry, last_error}).

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

effective() ->
    case persistent_term:get({?MODULE, effective}, undefined) of
        undefined -> {error, unavailable};
        Value -> {ok, Value}
    end.

status() -> gen_server:call(?MODULE, status, 1000).

cluster_status() ->
    Nodes = [node() | nodes()],
    Results = erpc:multicall(Nodes, ?MODULE, status, [], 1000),
    [case R of
         {ok, S} -> S#{node => N};
         _ -> #{node => N, state => <<"offline">>}
     end || {N, R} <- lists:zip(Nodes, Results)].

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

save(Revision, Settings, ResetSections, RequestedNode) ->
    gen_server:call(?MODULE, {save, Revision, Settings, ResetSections, RequestedNode}, 12000).

refresh() -> gen_server:call(?MODULE, refresh, 4000).

apply_current() -> gen_server:call(?MODULE, apply_current, ?ACK_TIMEOUT + 1000).

handle_ack(ConnId, Message) -> gen_server:cast(?MODULE, {ack, ConnId, Message}).

init([]) ->
    _ = (catch mnesia:subscribe({table, opconfig, simple})),
    State0 = #state{desired = #{}, effective = undefined, applied = #{}, pending = undefined},
    State = case bifrost_opconfig:snapshot(?KEY) of
        {ok, Snapshot} -> adopt(Snapshot, State0, quiet);
        error -> adopt(#{revision => 0, overrides => #{}, ptr_ttl_seconds => 21600,
                         retention_months => 6, source => deployment}, State0, quiet)
    end,
    self() ! reconcile,
    {ok, State}.

handle_call(status, _From, State) -> {reply, local_status(State), State};
handle_call(refresh, _From, State) ->
    Next = reconcile_db(State),
    {reply, ok, Next};
handle_call(apply_current, From, State) ->
    {noreply, send_current(State#state{pending = undefined}, From)};
handle_call({save, Revision, Settings, ResetSections, _Node}, _From, State) ->
    Reply = case overrides_from(Settings, ResetSections) of
        {ok, Overrides, Ptr, Retention} ->
            case compose(#{revision => Revision, overrides => Overrides,
                           ptr_ttl_seconds => Ptr, retention_months => Retention}) of
                {ok, _} ->
                    case bifrost_dns_settings_store:save(Revision, Overrides, Ptr, Retention) of
                        {ok, Saved} ->
                            case publish(Saved) of
                                ok -> {ok, Saved#{state => pending}};
                                {error, stale} -> {ok, Saved#{state => pending}};
                                {error, Reason} -> {saved_pending, Saved, Reason}
                            end;
                        {error, conflict} -> {error, conflict};
                        {error, Reason} -> {error, {database, Reason}}
                    end;
                {error, Reason} -> {error, {invalid, Reason}}
            end;
        {error, Reason} -> {error, {invalid, Reason}}
    end,
    {reply, Reply, State};
handle_call(_Request, _From, State) -> {reply, {error, unsupported}, State}.

handle_cast({ack, ConnId, Message}, State = #state{pending = {ConnId, Revision, Fingerprint, From, Timer}}) ->
    case Message of
        #{<<"type">> := <<"dns_settings_applied">>, <<"revision">> := Revision,
          <<"fingerprint">> := Fingerprint} ->
            cancel(Timer),
            reply(From, ok),
            {noreply, State#state{pending = undefined, last_error = undefined, retry = undefined,
                                  applied = #{revision => Revision, fingerprint => Fingerprint,
                                              at => erlang:system_time(second)}}};
        #{<<"type">> := <<"dns_settings_rejected">>, <<"revision">> := Revision,
          <<"fingerprint">> := Fingerprint} = Rejected ->
            cancel(Timer),
            Error = maps:get(<<"error">>, Rejected, <<"rejected">>),
            reply(From, {error, Error}),
            {noreply, schedule_retry(State#state{pending = undefined, last_error = Error})};
        _ -> {noreply, State}
    end;
handle_cast(_Msg, State) -> {noreply, State}.

handle_info({mnesia_table_event, {write, {opconfig, ?KEY, Snapshot}, _}}, State) ->
    {noreply, adopt(Snapshot, State, push)};
handle_info(reconcile, State) ->
    Next = reconcile_db(State),
    erlang:send_after(?RECONCILE_MS, self(), reconcile),
    {noreply, Next};
handle_info({ack_timeout, Ref}, State = #state{pending = {_, _, _, From, Ref}}) ->
    reply(From, {error, ack_timeout}),
    {noreply, schedule_retry(State#state{pending = undefined, last_error = <<"ack_timeout">>})};
handle_info(retry_apply, State) ->
    {noreply, send_current(State#state{retry = undefined}, undefined)};
handle_info(_Info, State) -> {noreply, State}.

reconcile_db(State) ->
    case bifrost_dns_settings_store:read() of
        {ok, Snapshot = #{revision := Revision}} ->
            Current = State#state.desired,
            case maps:get(revision, Current, -1) < Revision orelse
                 (maps:get(revision, Current, -1) =:= Revision andalso
                  maps:without([source], Current) =/= Snapshot) of
                true -> _ = publish(Snapshot), adopt(Snapshot, State, push);
                false -> State
            end;
        _ -> State
    end.

adopt(Snapshot, State, Mode) ->
    case valid_snapshot(Snapshot) andalso
         maps:get(revision, Snapshot) >= maps:get(revision, State#state.desired, -1) of
        false -> State;
        true ->
            case compose(Snapshot) of
                {ok, Effective} ->
                    persistent_term:put({?MODULE, effective}, Effective),
                    Next = State#state{desired = Snapshot, effective = Effective, last_error = undefined},
                    case Mode of push -> send_current(Next, undefined); quiet -> Next end;
                {error, Reason} ->
                    logger:error("refusing invalid DNS settings revision ~p: ~p",
                                 [maps:get(revision, Snapshot), Reason]),
                    State#state{last_error = Reason}
            end
    end.

send_current(State = #state{effective = undefined}, From) ->
    reply(From, {error, settings_unavailable}),
    State;
send_current(State = #state{effective = #{revision := Revision, fingerprint := Fingerprint,
                                          settings := Settings}}, From) ->
    case catch bifrost_socket_server:connection_id() of
        ConnId when ConnId =/= undefined, not is_tuple(ConnId) ->
            Msg = #{type => <<"apply_dns_settings">>, revision => Revision,
                    fingerprint => Fingerprint, settings => Settings},
            case catch bifrost_socket_server:send_message(Msg) of
                ok ->
                    Ref = make_ref(),
                    erlang:send_after(?ACK_TIMEOUT, self(), {ack_timeout, Ref}),
                    State#state{pending = {ConnId, Revision, Fingerprint, From, Ref}};
                Error ->
                    reply(From, {error, Error}),
                    schedule_retry(State#state{last_error = <<"send_failed">>})
            end;
        _ ->
            reply(From, {error, not_connected}),
            State
    end.

compose(Snapshot = #{revision := Revision, overrides := Overrides,
                     ptr_ttl_seconds := Ptr, retention_months := Retention}) ->
    Config = case catch bifrost_config_server:get_config() of {ok, C} -> C; _ -> #{} end,
    case bifrost_dns_settings:defaults(Config) of
        {ok, Defaults} ->
            Merged0 = maps:merge(Defaults, maps:with(?SECTIONS, Overrides)),
            Reverse = maps:get(<<"reverse_dns">>, Merged0),
            Merged = Merged0#{<<"reverse_dns">> => Reverse#{<<"positive_ttl_seconds">> => Ptr},
                              <<"retention_months">> => Retention},
            case bifrost_dns_settings:validate(Merged) of
                {ok, Settings} ->
                    Policy = maps:without([<<"retention_months">>], Settings),
                    Digest = crypto:hash(sha256, term_to_binary(Policy, [deterministic])),
                    Fingerprint = binary:part(binary:encode_hex(Digest, lowercase), 0, 32),
                    Sources = maps:from_list([{S, case maps:is_key(S, Overrides) of
                                                      true -> <<"postgres">>;
                                                      false -> <<"deployment">>
                                                  end} || S <- ?SECTIONS]),
                    {ok, #{revision => Revision, fingerprint => Fingerprint, settings => Settings,
                           defaults => Defaults#{<<"retention_months">> => 6},
                           overrides => Overrides, sources => Sources,
                           snapshot_source => maps:get(source, Snapshot, postgres)}};
                Error -> Error
            end;
        Error -> Error
    end.

overrides_from(Settings0, ResetSections) when is_map(Settings0), is_list(ResetSections) ->
    try
        {ok, Settings} = bifrost_dns_settings:validate(Settings0),
        true = lists:all(fun(S) -> lists:member(S, ?SECTIONS) end, ResetSections),
        Config = case catch bifrost_config_server:get_config() of {ok, C} -> C; _ -> #{} end,
        {ok, Defaults} = bifrost_dns_settings:defaults(Config),
        Overrides = maps:from_list([{S, maps:get(S, Settings)} || S <- ?SECTIONS,
            not lists:member(S, ResetSections), maps:get(S, Settings) =/= maps:get(S, Defaults)]),
        Ptr = maps:get(<<"positive_ttl_seconds">>, maps:get(<<"reverse_dns">>, Settings)),
        Retention = maps:get(<<"retention_months">>, Settings),
        {ok, Overrides, Ptr, Retention}
    catch _:_ -> {error, <<"invalid_settings">>}
    end;
overrides_from(_, _) -> {error, <<"invalid_settings">>}.

valid_snapshot(#{revision := R, overrides := O, ptr_ttl_seconds := P, retention_months := M})
  when is_integer(R), R >= 0, is_map(O), is_integer(P), P > 0, is_integer(M), M >= 0 -> true;
valid_snapshot(_) -> false.

local_status(#state{desired = D, effective = E0, applied = A, pending = P, last_error = Err}) ->
    E = case E0 of undefined -> #{}; _ -> E0 end,
    #{desired_revision => maps:get(revision, D, undefined),
      desired_fingerprint => maps:get(fingerprint, E, undefined),
      applied_revision => maps:get(revision, A, undefined),
      applied_fingerprint => maps:get(fingerprint, A, undefined),
      state => case {P, A} of
                   {undefined, #{fingerprint := F}} when is_map_key(fingerprint, E),
                                                        F =:= map_get(fingerprint, E) -> <<"applied">>;
                   {undefined, _} -> <<"pending">>;
                   _ -> <<"applying">>
               end,
      last_error => Err}.

schedule_retry(State = #state{retry = undefined}) ->
    State#state{retry = erlang:send_after(5000, self(), retry_apply)};
schedule_retry(State) -> State.

cancel(Ref) -> erlang:cancel_timer(Ref).
reply(undefined, _) -> ok;
reply(From, Reply) -> gen_server:reply(From, Reply).

-module(bifrost_config_server).
-behaviour(gen_server).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([get_config/0, get_protection/0, set_protection/1, set_protection/2,
         protection_message/0]).

%% The filtering pause is CLUSTER state, kept in the replicated `opconfig`
%% Mnesia table (disc_copies). Every node's config_server follows it: a change on
%% any node replicates, each node applies it to its own Rust and arms its own
%% expiry timer, and hydration re-applies it to a restarted Rust. It was
%% node-local before: behind a load balancer "pause" hit one random pod, the
%% header disagreed per pod, and a Rust restart silently re-enabled filtering
%% while the UI still said paused.

-define(KEY, protection).

-record(state, {
    config :: map(),
    protection_enabled :: boolean(),
    protection_timer :: undefined | reference(),
    protection_until :: undefined | integer()  %% Unix timestamp when protection re-enables
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    logger:info("~s started", [?MODULE]),
    ConfigPath = os:getenv("BIFROST_CONFIG_PATH", "/etc/bifrost/config.yaml"),
    Config = case file:consult(ConfigPath) of
        {ok, Terms} ->
            maps:from_list(Terms);
        {error, Reason} ->
            logger:warning("failed to read config from ~s: ~p", [ConfigPath, Reason]),
            #{}
    end,
    logger:info("config_server started, config loaded: ~p keys", [map_size(Config)]),
    _ = (catch mnesia:subscribe({table, opconfig, simple})),
    State0 = #state{config = Config, protection_enabled = true},
    %% Adopt the cluster's current pause (it survives restarts). Rust is not
    %% connected yet; hydration sends it via protection_message/0.
    {ok, adopt(stored(), State0, quiet)}.

get_config() ->
    gen_server:call(?MODULE, get_config).

get_protection() ->
    gen_server:call(?MODULE, get_protection).

%% Enable protection (no duration)
set_protection(true) ->
    gen_server:call(?MODULE, {set_protection, true, undefined});
%% Disable protection indefinitely
set_protection(false) ->
    gen_server:call(?MODULE, {set_protection, false, undefined}).

%% Disable protection for N seconds
set_protection(false, DurationSecs) when is_integer(DurationSecs), DurationSecs > 0 ->
    gen_server:call(?MODULE, {set_protection, false, DurationSecs});
set_protection(true, _) ->
    set_protection(true).

%% The set_protection IPC message for the cluster's current state. Read from
%% the replicated table directly, so hydration never needs a call into this
%% process.
protection_message() ->
    #{enabled := Enabled} = stored(),
    #{type => <<"set_protection">>, enabled => Enabled}.

handle_call(get_config, _From, State = #state{config = Config}) ->
    {reply, {ok, Config}, State};

handle_call(get_protection, _From, State = #state{protection_enabled = Enabled, protection_until = Until}) ->
    UntilValue = case Until of undefined -> null; V -> V end,
    {reply, {ok, #{enabled => Enabled, until => UntilValue}}, State};

handle_call({set_protection, Enabled, DurationSecs}, _From, State) ->
    Until = case {Enabled, DurationSecs} of
        {false, D} when is_integer(D) -> erlang:system_time(second) + D;
        _ -> undefined
    end,
    Value = #{enabled => Enabled, until => Until},
    %% Applied here immediately (the caller reads it back), and replicated so
    %% every other node applies it from its table event.
    bifrost_opconfig:store(?KEY, Value),
    logger:info("protection set: ~p", [Value]),
    {reply, ok, adopt(Value, State, push)};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_info({mnesia_table_event, {write, {opconfig, ?KEY, Value}, _}}, State) ->
    {noreply, adopt(Value, State, push)};

%% Only the timer for the CURRENT deadline may end the pause: a stale timer from
%% an earlier, replaced pause must not cut a newer one short.
handle_info({protection_expired, Until}, State = #state{protection_until = Until}) ->
    Value = #{enabled => true, until => undefined},
    bifrost_opconfig:store(?KEY, Value),
    logger:info("protection re-enabled (timer expired)"),
    {noreply, adopt(Value, State, push)};
handle_info({protection_expired, _Stale}, State) ->
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Internal

%% The stored pause, with an elapsed deadline read as "enabled".
stored() ->
    Now = erlang:system_time(second),
    case bifrost_opconfig:snapshot(?KEY) of
        {ok, #{enabled := false, until := U}} when is_integer(U), U =< Now ->
            #{enabled => true, until => undefined};
        {ok, #{enabled := _, until := _} = V} -> V;
        _ -> #{enabled => true, until => undefined}
    end.

adopt(#{enabled := Enabled, until := Until}, State = #state{protection_timer = Old}, Mode) ->
    cancel_timer(Old),
    case Mode of
        push -> send_protection(Enabled);
        quiet -> ok
    end,
    Timer = case {Enabled, Until} of
        {false, U} when is_integer(U) ->
            Ms = max(0, (U - erlang:system_time(second)) * 1000),
            erlang:send_after(Ms, self(), {protection_expired, U});
        _ -> undefined
    end,
    State#state{protection_enabled = Enabled, protection_until = Until, protection_timer = Timer}.

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).

send_protection(Enabled) ->
    catch bifrost_socket_server:send_message(#{type => <<"set_protection">>, enabled => Enabled}).

%% Periodic PTR warmer. Resolves reverse-DNS names for recently-active client
%% IPs on an interval so friendly names populate the Dashboard (Top Clients) and
%% Query Log without depending on anyone opening the Clients page. All real work
%% lives in bifrost_ptr:warm/0; this process only schedules it. A no-op when
%% `ptr_resolver` is unset (PTR disabled).
%%
%% CLUSTER SINGLETON: every node runs this GenServer, but PTR data lives in the
%% shared Postgres, so only ONE node must warm each tick — otherwise N nodes fire
%% N× redundant lookups at the gateway resolver for the same IPs. We elect a
%% single leader across the cluster via `global` name registration. Each tick,
%% the node that holds (or can claim) the global name warms; the rest skip. On
%% leader death `global` frees the name and the next survivor's tick claims it —
%% no extra infrastructure, self-healing. Single-node dev: that node is always
%% the leader.
-module(bifrost_ptr_warmer).
-behaviour(gen_server).

-export([start_link/0, warm_now/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(INTERVAL, 300000).      %% 5 minutes
-define(FIRST_DELAY, 15000).    %% first pass 15s after boot (let hydration finish)
-define(LEADER, bifrost_ptr_warmer_leader).  %% cluster-wide global singleton name

-record(state, {timer :: reference()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Trigger an immediate warm pass (e.g. after a config change).
warm_now() ->
    gen_server:cast(?MODULE, warm).

init([]) ->
    logger:info("~s started", [?MODULE]),
    %% This process owns the PTR in-flight table: it must outlive every caller
    %% of bifrost_ptr:resolve_async/1, including short-lived web requests.
    ok = bifrost_ptr:init_inflight(),
    %% React to peer loss so a dead leader is replaced promptly, not on the
    %% next 5-min tick.
    net_kernel:monitor_nodes(true),
    Timer = erlang:send_after(?FIRST_DELAY, self(), warm),
    {ok, #state{timer = Timer}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(warm, State) ->
    do_warm(),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(warm, #state{timer = Old} = State) ->
    cancel(Old),
    %% Only the cluster leader warms on the timer; standbys skip this tick.
    case is_leader() of
        true -> do_warm();
        false -> ok
    end,
    Timer = erlang:send_after(?INTERVAL, self(), warm),
    {noreply, State#state{timer = Timer}};
handle_info({nodedown, _Node}, State) ->
    %% A node left; the leader may be gone. Try to claim and, if we win, warm now.
    case is_leader() of
        true -> do_warm();
        false -> ok
    end,
    {noreply, State};
handle_info({nodeup, _Node}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

is_leader() -> bifrost_cluster:is_leader(?LEADER).

do_warm() ->
    try bifrost_ptr:warm() of
        {ok, N} when N > 0 -> logger:debug("ptr warmer queued ~p lookups", [N]);
        _ -> ok
    catch
        Class:Reason -> logger:warning("ptr warm failed: ~p:~p", [Class, Reason])
    end.

cancel(Ref) -> erlang:cancel_timer(Ref).

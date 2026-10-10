-module(bifrost_socket_server).
-behaviour(gen_server).

%% Erlang end of the Rust IPC. Exactly ONE client: Rust opens a single
%% bidirectional connection and both control messages (out) and events (in)
%% travel on it. A new connection means a new (or reconnected) Rust process, so
%% it replaces the old one and always triggers full re-hydration.

-export([start_link/0, start_link/1, send_message/1, connection_id/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

%% A Rust process that stops reading must make sends fail instead of blocking
%% the caller (hydration, API handlers) forever. The socket is closed on
%% timeout; Rust reconnects and is re-hydrated from scratch.
-define(DEFAULT_SEND_TIMEOUT, 5000).

-record(state, {
    listen_socket :: gen_tcp:socket(),
    client :: gen_tcp:socket() | undefined,
    connection_id :: reference() | undefined,
    socket_path :: string()
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

start_link(SocketPath) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [SocketPath], []).

send_message(Data) when is_map(Data) ->
    gen_server:call(?MODULE, {send, Data}, infinity).

connection_id() ->
    gen_server:call(?MODULE, connection_id, 1000).

init([]) ->
    SocketPath = case catch bifrost_config_server:get_config() of
        {ok, Config} ->
            Network = maps:get(network, Config, #{}),
            proplists:get_value(unix_socket_path, Network, "/run/bifrost/ipc.sock");
        _ ->
            "/run/bifrost/ipc.sock"
    end,
    init([SocketPath]);
init([SocketPath]) ->
    logger:info("~s started", [?MODULE]),
    filelib:ensure_dir(SocketPath),
    _ = file:delete(SocketPath),
    %% active=false on the listener: an accepted socket must not deliver data to
    %% the acceptor before ownership moves to this process.
    case gen_tcp:listen(0, [{ifaddr, {local, SocketPath}}, binary, {packet, 4},
                            {active, false}]) of
        {ok, ListenSocket} ->
            logger:info("Unix socket server listening on ~s", [SocketPath]),
            Server = self(),
            spawn_link(fun() -> acceptor(Server, ListenSocket) end),
            {ok, #state{listen_socket = ListenSocket, socket_path = SocketPath}};
        {error, Reason} ->
            {stop, {listen_failed, Reason}}
    end.

%% Blocks in accept OUTSIDE the gen_server, so sends are never stalled waiting
%% for a connection, then hands each socket over.
acceptor(Server, Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, Sock} ->
            ok = gen_tcp:controlling_process(Sock, Server),
            Server ! {accepted, Sock},
            acceptor(Server, Listen);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:error("IPC accept failed: ~p, retrying", [Reason]),
            timer:sleep(200),
            acceptor(Server, Listen)
    end.

handle_call(connection_id, _From, State = #state{connection_id = Id}) ->
    {reply, Id, State};
handle_call({send, _Data}, _From, State = #state{client = undefined}) ->
    {reply, {error, not_connected}, State};
handle_call({send, Data}, _From, State = #state{client = Sock}) ->
    case gen_tcp:send(Sock, jsx:encode(Data)) of
        ok ->
            {reply, ok, State};
        {error, Reason} ->
            logger:warning("IPC send failed (~p), dropping Rust connection", [Reason]),
            gen_tcp:close(Sock),
            {reply, {error, Reason}, State#state{client = undefined, connection_id = undefined}}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({accepted, Sock}, State = #state{client = Old}) ->
    case Old of
        undefined -> ok;
        _ ->
            logger:info("new Rust connection replaces the previous one"),
            gen_tcp:close(Old)
    end,
    Timeout = application:get_env(bifrost, ipc_send_timeout, ?DEFAULT_SEND_TIMEOUT),
    ok = inet:setopts(Sock, [{active, true}, {send_timeout, Timeout},
                             {send_timeout_close, true}]),
    logger:info("Rust client connected"),
    Id = make_ref(),
    bifrost_blocklist_manager:on_client_connected(),
    {noreply, State#state{client = Sock, connection_id = Id}};
handle_info({tcp, Sock, Data}, State = #state{client = Sock, connection_id = Id}) ->
    handle_inbound(Data, Id),
    {noreply, State};
handle_info({tcp_closed, Sock}, State = #state{client = Sock}) ->
    logger:info("Rust client disconnected"),
    {noreply, State#state{client = undefined, connection_id = undefined}};
handle_info({tcp_error, Sock, Reason}, State = #state{client = Sock}) ->
    logger:warning("Rust client error: ~p", [Reason]),
    gen_tcp:close(Sock),
    {noreply, State#state{client = undefined, connection_id = undefined}};
handle_info(_Info, State) ->
    %% Includes late messages from a replaced socket.
    {noreply, State}.

%% One bad inbound message must never take the IPC down: decoding AND dispatch
%% are both inside the try (a Mnesia abort in write_cache_entry used to escape
%% from the `of` body and crash the server, dropping the Rust connection).
handle_inbound(Data, ConnId) ->
    try jsx:decode(iolist_to_binary(Data), [return_maps]) of
        Msg -> dispatch(Msg, ConnId)
    catch
        _:_ -> logger:warning("dropping undecodable IPC frame")
    end.

dispatch(#{<<"type">> := Type} = Ack, ConnId)
  when Type =:= <<"dns_settings_applied">>; Type =:= <<"dns_settings_rejected">> ->
    bifrost_dns_settings_server:handle_ack(ConnId, Ack);
dispatch(#{<<"type">> := <<"cache_store">>} = CacheStore, _ConnId) ->
    try bifrost_mnesia:write_cache_entry(CacheStore)
    catch C:R -> logger:debug("cache propagation write failed: ~p:~p", [C, R])
    end;
dispatch(Event, _ConnId) ->
    gen_server:cast(bifrost_query_writer, {query_event, Event}).

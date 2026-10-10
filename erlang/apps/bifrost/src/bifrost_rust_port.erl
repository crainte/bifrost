-module(bifrost_rust_port).
-behaviour(gen_server).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
    port :: port() | undefined
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    logger:info("~s started", [?MODULE]),
    RustBin = os:getenv("BIFROST_RUST_BIN", "/usr/local/bin/bifrost-resolver"),
    logger:info("starting Rust binary: ~s", [RustBin]),
    Port = open_port({spawn_executable, RustBin}, [
        {args, []},
        exit_status,
        stderr_to_stdout
    ]),
    OsPid = case erlang:port_info(Port, os_pid) of
        {os_pid, Pid} -> Pid;
        undefined -> unknown
    end,
    logger:info("Rust process spawned, OS pid: ~p", [OsPid]),
    {ok, #state{port = Port}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_info({Port, {data, Data}}, State = #state{port = Port}) ->
    logger:info("Rust stdout/stderr: ~s", [Data]),
    {noreply, State};
handle_info({Port, {exit_status, Status}}, State = #state{port = Port}) ->
    logger:error("Rust process exited with status ~p, stopping for supervisor restart", [Status]),
    {stop, {rust_exit, Status}, State};
handle_info(_Info, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

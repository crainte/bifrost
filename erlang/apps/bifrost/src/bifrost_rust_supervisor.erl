-module(bifrost_rust_supervisor).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },

    RustPort = #{
        id => rust_port,
        start => {bifrost_rust_port, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    SocketServer = #{
        id => socket_server,
        start => {bifrost_socket_server, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    Children = [SocketServer, RustPort],

    {ok, {SupFlags, Children}}.

-module(bifrost_web_server).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 1,
        period => 5
    },

    %% Cowboy HTTP listener on port 8081
    Routes = bifrost_router:routes(),
    Dispatch = cowboy_router:compile(Routes),
    {ok, _} = cowboy:start_clear(bifrost_http_listener, [
        {port, 8081}
    ], #{
        env => #{dispatch => Dispatch},
        %% Auth runs after routing (needs the resolved path) and before the
        %% handler. cowboy_router populates the path; bifrost_auth_middleware
        %% gates it; cowboy_handler then dispatches.
        middlewares => [cowboy_router, bifrost_auth_middleware, cowboy_handler]
    }),
    logger:info("web server listening on port 8081"),

    Children = [],
    {ok, {SupFlags, Children}}.

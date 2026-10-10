-module(bifrost_app).
-behaviour(application).
-export([start/2, stop/1, check_cookie/2]).

start(_StartType, _StartArgs) ->
    case check_cookie(bifrost_cluster:clustered(), erlang:get_cookie()) of
        ok ->
            %% Start Mnesia before the supervisor tree so blocklist_manager
            %% can read from the cache table immediately.
            bifrost_mnesia:init_tables(),
            bifrost_sup:start_link();
        {error, weak_cluster_cookie} = Error ->
            logger:critical("refusing to start: clustering is configured but the Erlang "
                            "cookie is a placeholder or shorter than 32 bytes. Anyone who "
                            "can reach epmd/the distribution port could run code on this "
                            "node. Set BIFROST_COOKIE from `openssl rand -hex 32`."),
            Error
    end.

stop(_State) ->
    mnesia:stop(),
    ok.

%% The cookie is the ONLY authentication between Erlang nodes, and a node that
%% accepts a connection grants the peer full code execution. A clustered node
%% therefore refuses a weak or placeholder cookie. Single-node dev (no
%% BIFROST_CLUSTER_* set) keeps the convenient default.
-spec check_cookie(boolean(), atom()) -> ok | {error, weak_cluster_cookie}.
check_cookie(false, _Cookie) ->
    ok;
check_cookie(true, Cookie) ->
    case bifrost_auth:strong_secret(atom_to_binary(Cookie, utf8)) of
        true -> ok;
        false -> {error, weak_cluster_cookie}
    end.

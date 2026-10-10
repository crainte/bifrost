-module(bifrost_sup).
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

    ConfigServer = #{
        id => config_server,
        start => {bifrost_config_server, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    DbPool = #{
        id => db_pool,
        start => {bifrost_db_pool, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    ClusterManager = #{
        id => cluster,
        start => {bifrost_cluster, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    DnsSettings = #{
        id => dns_settings,
        start => {bifrost_dns_settings_server, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    BlocklistManager = #{
        id => blocklist_manager,
        start => {bifrost_blocklist_manager, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    RustSupervisor = #{
        id => rust_supervisor,
        start => {bifrost_rust_supervisor, start_link, []},
        type => supervisor,
        restart => permanent,
        shutdown => 5000
    },

    UpstreamMonitor = #{
        id => upstream_monitor,
        start => {bifrost_upstream_monitor, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    %% Dedicated connection for query_log writes, so per-query logging and the
    %% dashboard never queue behind each other on one connection.
    DbWriter = #{
        id => db_writer,
        start => {bifrost_db_pool, start_link, [bifrost_db_writer]},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    QueryWriter = #{
        id => query_writer,
        start => {bifrost_query_writer, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    DomainAnalyzer = #{
        id => domain_analyzer,
        start => {bifrost_domain_analyzer, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },

    PtrWarmer = #{
        id => ptr_warmer,
        start => {bifrost_ptr_warmer, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },
    LoginLimiter = #{
        id => login_limiter,
        start => {bifrost_login_limiter, start_link, []},
        type => worker,
        restart => permanent,
        shutdown => 5000
    },
    WebServer = #{
        id => web_server,
        start => {bifrost_web_server, start_link, []},
        type => supervisor,
        restart => permanent,
        shutdown => 5000
    },

    Children = [
        ConfigServer,
        DbPool,
        ClusterManager,
        DnsSettings,
        BlocklistManager,
        RustSupervisor,
        UpstreamMonitor,
        DbWriter,
        QueryWriter,
        DomainAnalyzer,
        PtrWarmer,
        LoginLimiter,
        WebServer
    ],

    {ok, {SupFlags, Children}}.

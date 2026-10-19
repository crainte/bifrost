-module(bifrost_router).

-export([routes/0]).

routes() ->
    [
        {'_', [
            %% Auth (exempt from the auth middleware itself)
            {"/login",                bifrost_auth_handler, login},
            {"/logout",               bifrost_auth_handler, logout},
            {"/static/bifrost-icon.png", cowboy_static,
                {priv_file, bifrost, "static/bifrost-icon.png"}},
            {"/static/bifrost-wordmark.png", cowboy_static,
                {priv_file, bifrost, "static/bifrost-wordmark.png"}},
            {"/static/bifrost.css", cowboy_static,
                {priv_file, bifrost, "static/bifrost.css"}},
            %% UI pages
            {"/",                     bifrost_ui_handler, redirect},
            {"/dashboard",            bifrost_ui_handler, dashboard},
            {"/blocklists",           bifrost_ui_handler, blocklists},
            {"/query-log",            bifrost_ui_handler, query_log},
            {"/clients",              bifrost_ui_handler, clients},
            {"/filters",              bifrost_ui_handler, filters},
            {"/threats",              bifrost_ui_handler, threats},

            {"/settings",             bifrost_ui_handler, settings},
            {"/api/settings",         bifrost_settings_handler, settings},
            {"/api/protection",       bifrost_api_handler, [protection]},
            {"/api/stats",            bifrost_api_handler, [stats]},
            {"/api/stats/trends",     bifrost_api_handler, [stats_trends]},
            {"/api/cache/evict",      bifrost_api_handler, [cache_evict]},
            {"/api/blocks",           bifrost_api_handler, [manual_block]},
            {"/api/unblock",          bifrost_api_handler, [unblock]},
            {"/api/client-blocks",    bifrost_api_handler, [client_block]},
            {"/api/threats",          bifrost_api_handler, [threats]},
            {"/api/threats/block",    bifrost_api_handler, [threats_block]},
            {"/api/threats/dismiss",  bifrost_api_handler, [threats_dismiss]},
            {"/api/threats/campaigns", bifrost_api_handler, [threat_campaigns]},
            {"/api/threats/campaigns/dismiss", bifrost_api_handler, [threat_campaigns_dismiss]},
            {"/api/threats/suppressions/revoke", bifrost_api_handler, [threat_suppressions_revoke]},
            {"/api/threats/scan",     bifrost_api_handler, [threats_scan]},
            {"/api/threats/settings", bifrost_api_handler, [threats_settings]},
            {"/api/blocklists/refresh", bifrost_api_handler, [blocklists_refresh]},
            {"/api/blocklists",       bifrost_api_handler, [blocklists]},
            {"/api/blocklists/builtin", bifrost_api_handler, [blocklists_builtin]},
            {"/api/blocklists/add",   bifrost_api_handler, [blocklists_add]},
            {"/api/blocklists/analyze", bifrost_api_handler, [blocklists_analyze]},
            {"/api/blocklists/:name/toggle", bifrost_api_handler, [blocklists_toggle]},
            {"/api/blocklists/:name", bifrost_api_handler, [blocklists_delete]},
            {"/api/query-log",        bifrost_api_handler, [query_log]},
            {"/api/clients",          bifrost_api_handler, [clients]},
            {"/api/cluster",          bifrost_api_handler, [cluster]},
            {"/api/health",           bifrost_api_handler, [health]},
            %% Liveness: exempt from auth and independent of Postgres. k8s
            %% probes MUST NOT point at a gated route — a 401 is outside the
            %% 200-399 success range, so the pod never passes startup.
            {"/api/health/live",      bifrost_api_handler, [health_live]},
            {"/api/query-log/table",     bifrost_api_handler, [query_log, table]},
            {"/api/clients/:ip",      bifrost_api_handler, [clients_update]},
            {"/api/clients/:ip/suspicious", bifrost_api_handler, [clients_suspicious]},
            {"/api/rewrites",         bifrost_api_handler, [rewrites]},
            {"/api/rewrites/:domain",  bifrost_api_handler, [rewrites_delete]},
            {"/api/allowlist",        bifrost_api_handler, [allowlist]},
            {"/api/allowlist/:domain", bifrost_api_handler, [allowlist_delete]}
        ]}
    ].

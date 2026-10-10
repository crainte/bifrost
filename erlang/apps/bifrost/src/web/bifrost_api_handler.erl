-module(bifrost_api_handler).

-export([init/2, push_rewrites/0, push_allowlist/0, push_manual_blocks/0, push_client_blocks/0]).
-export([score_domain/2, score_reasons/2, rdap_lookup/1, rdap_cached/1,
         rdap_reasons/1, score_rdap/1, enrich_with_rdap/1, extract_base_domain/1]).

-define(JSON, #{<<"content-type">> => <<"application/json">>}).
%% One window for every "recent activity" figure (dashboard, query log default,
%% clients), so the pages never disagree about the same traffic.
-define(STATS_WINDOW, "90 days").
-define(LAST_SEEN, "to_char(MAX(q.queried_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_seen ").

init(Req0, State) ->
    try
        handle_request(cowboy_req:method(Req0), Req0, State)
    catch
        Class:Reason:Stack ->
            logger:error("api handler crashed: ~p:~p~n~p", [Class, Reason, Stack]),
            respond(500, #{error => <<"internal error">>}, Req0)
    end.

%% ── Dispatch ─────────────────────────────────────────────────

handle_request(<<"GET">>, Req0, [stats]) ->
    Stats = get_stats(),
    respond(200, Stats, Req0);

handle_request(<<"GET">>, Req0, [stats_trends]) ->
    Trends = get_query_trends(),
    respond(200, #{trends => Trends}, Req0);

handle_request(<<"GET">>, Req0, [protection]) ->
    {ok, Status} = bifrost_config_server:get_protection(),
    respond(200, Status, Req0);

handle_request(<<"POST">>, Req0, [protection]) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"enabled">> := true} ->
            ok = bifrost_config_server:set_protection(true),
            respond(200, #{ok => true, enabled => true}, Req1);
        #{<<"enabled">> := false, <<"duration">> := Duration} when is_integer(Duration) ->
            ok = bifrost_config_server:set_protection(false, Duration),
            Until = erlang:system_time(second) + Duration,
            respond(200, #{ok => true, enabled => false, until => Until}, Req1);
        #{<<"enabled">> := false} ->
            ok = bifrost_config_server:set_protection(false),
            respond(200, #{ok => true, enabled => false, until => null}, Req1);
        _ ->
            respond(400, #{error => <<"invalid body">>}, Req1)
    end;

handle_request(<<"POST">>, Req0, [cache_evict]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Domain} when is_binary(Domain), Domain =/= <<>> ->
            bifrost_mnesia:broadcast_evict(Domain),
            respond(200, #{ok => true, domain => Domain}, Req0);
        _ ->
            respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [manual_block]) ->
    case db_call(query, "SELECT domain FROM manual_blocks ORDER BY added_at DESC") of
        {ok, _, Rows} when is_list(Rows) ->
            respond(200, #{domains => [D || {D} <- Rows]}, Req0);
        _ ->
            respond(200, #{domains => []}, Req0)
    end;

handle_request(<<"POST">>, Req0, [manual_block]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw} ->
            with_domain(Raw, Req0, fun(Domain) -> block_domain(Domain, Req0) end);
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

%% Unblock = allowlist the domain (overrides all blocklists) AND drop any
%% manual block, so the two lists never disagree. Cannot touch URL-fetched
%% blocklists; the allowlist entry is the override for those.
handle_request(<<"POST">>, Req0, [unblock]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw} ->
            with_domain(Raw, Req0, fun(Domain) -> allow_domain(Domain, Req0) end);
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"DELETE">>, Req0, [manual_block]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw} ->
            with_domain(Raw, Req0, fun(Domain) ->
                case db_call(equery, "DELETE FROM manual_blocks WHERE domain = $1", [Domain]) of
                    {ok, _} ->
                        push_manual_blocks(),
                        bifrost_mnesia:broadcast_config_reload(),
                        bifrost_mnesia:broadcast_evict(Domain),
                        respond(200, #{ok => true}, Req0);
                    _ -> respond(500, #{error => <<"db error">>}, Req0)
                end
            end);
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [client_block]) ->
    case db_call(query, "SELECT client_ip, domain FROM client_blocks ORDER BY client_ip, domain") of
        {ok, _, Rows} when is_list(Rows) ->
            respond(200, #{blocks => [#{client_ip => ip_to_binary(Ip), domain => D} || {Ip, D} <- Rows]}, Req0);
        _ ->
            respond(503, #{error => <<"database unavailable">>}, Req0)
    end;

handle_request(<<"POST">>, Req0, [client_block]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"client_ip">> := Ip, <<"domain">> := Raw} when is_binary(Ip), Ip =/= <<>> ->
            case {parse_ip(Ip), bifrost_domain:normalize(Raw)} of
                {_, error} -> respond(400, #{error => <<"invalid domain">>}, Req0);
                {{ok, IpTuple}, {ok, Domain}} ->
                    case db_call(equery, "INSERT INTO client_blocks (client_ip, domain) VALUES ($1, $2) ON CONFLICT DO NOTHING", [IpTuple, Domain]) of
                        {ok, _} ->
                            push_client_blocks(),
                            bifrost_mnesia:broadcast_config_reload(),
                            bifrost_mnesia:broadcast_evict(Domain),
                            respond(200, #{ok => true}, Req0);
                        _ -> respond(500, #{error => <<"db error">>}, Req0)
                    end;
                {error, _} -> respond(400, #{error => <<"invalid client_ip">>}, Req0)
            end;
        _ -> respond(400, #{error => <<"missing client_ip or domain">>}, Req0)
    end;

handle_request(<<"DELETE">>, Req0, [client_block]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"client_ip">> := Ip, <<"domain">> := Raw} when is_binary(Ip), Ip =/= <<>> ->
            case {parse_ip(Ip), bifrost_domain:normalize(Raw)} of
                {_, error} -> respond(400, #{error => <<"invalid domain">>}, Req0);
                {error, _} -> respond(400, #{error => <<"invalid client_ip">>}, Req0);
                {{ok, IpTuple}, {ok, Domain}} ->
                    case db_call(equery, "DELETE FROM client_blocks WHERE client_ip = $1 AND domain = $2", [IpTuple, Domain]) of
                        {ok, _} ->
                            push_client_blocks(),
                            bifrost_mnesia:broadcast_config_reload(),
                            bifrost_mnesia:broadcast_evict(Domain),
                            respond(200, #{ok => true}, Req0);
                        _ -> respond(500, #{error => <<"db error">>}, Req0)
                    end
            end;
        _ -> respond(400, #{error => <<"missing client_ip or domain">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [threats]) ->
    Threats = get_threats(),
    respond(200, #{threats => Threats}, Req0);

handle_request(<<"POST">>, Req0, [threats_block]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw} ->
            with_domain(Raw, Req0, fun(Domain) ->
                _ = db_call(equery, "UPDATE suspicious_candidates SET status='blocked', updated_at=now() WHERE domain=$1", [Domain]),
                block_domain(Domain, Req0)
            end);
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"POST">>, Req0, [threats_dismiss]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Domain} when is_binary(Domain), Domain =/= <<>> ->
            case db_call(equery, "UPDATE suspicious_candidates SET status='dismissed', updated_at=now() WHERE domain=$1", [Domain]) of
                {ok, _} -> respond(200, #{ok => true}, Req0);
                _ -> respond(500, #{error => <<"db error">>}, Req0)
            end;
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"POST">>, Req0, [threats_scan]) ->
    bifrost_domain_analyzer:scan_now(),
    respond(200, #{ok => true}, Req0);

handle_request(<<"GET">>, Req0, [threats_settings]) ->
    respond(200, get_threat_settings(), Req0);

handle_request(<<"POST">>, Req0, [threats_settings]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        Map when is_map(Map) ->
            maps:foreach(fun(K, V) ->
                case lists:member(K, [<<"auto_block_enabled">>, <<"auto_block_min_score">>,
                                      <<"auto_block_max_age_days">>]) of
                    true ->
                        VBin = if is_binary(V) -> V; true -> list_to_binary(io_lib:format("~p", [V])) end,
                        _ = db_call(equery,
                            "INSERT INTO settings (key, value) VALUES ($1, $2) "
                            "ON CONFLICT (key) DO UPDATE SET value = $2", [K, VBin]);
                    false -> ok
                end
            end, Map),
            respond(200, get_threat_settings(), Req0);
        _ -> respond(400, #{error => <<"invalid body">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [blocklists]) ->
    Lists = get_blocklists(),
    respond(200, #{blocklists => Lists}, Req0);

handle_request(<<"POST">>, Req0, [blocklists_refresh]) ->
    bifrost_blocklist_manager:force_refresh(),
    respond(200, #{ok => true}, Req0);

handle_request(<<"POST">>, Req0, [blocklists_toggle]) ->
    #{name := Name} = cowboy_req:bindings(Req0),
    case toggle_blocklist(Name) of
        ok -> respond(200, #{ok => true}, Req0);
        {error, Reason} -> respond(400, #{error => Reason}, Req0)
    end;

handle_request(<<"GET">>, Req0, [blocklists_builtin]) ->
    Catalog = get_builtin_blocklists(),
    respond(200, Catalog, Req0);

handle_request(<<"POST">>, Req0, [blocklists_add]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"name">> := Name, <<"url">> := Url} ->
            case add_blocklist(Name, Url) of
                ok -> respond(200, #{ok => true}, Req0);
                {error, Reason} -> respond(400, #{error => Reason}, Req0)
            end;
        _ ->
            respond(400, #{error => <<"name and url required">>}, Req0)
    end;
handle_request(<<"GET">>, Req0, [blocklists_analyze]) ->
    Analysis = analyze_blocklists(),
    respond(200, Analysis, Req0);

handle_request(<<"DELETE">>, Req0, [blocklists_delete]) ->
    #{name := Name} = cowboy_req:bindings(Req0),
    case delete_blocklist(Name) of
        ok -> respond(200, #{ok => true}, Req0);
        {error, Reason} -> respond(400, #{error => Reason}, Req0)
    end;

handle_request(<<"GET">>, Req0, [query_log]) ->
    QS = cowboy_req:parse_qs(Req0),
    {Entries, Total} = query_log(QS),
    respond(200, #{entries => Entries, total => Total}, Req0);
handle_request(<<"GET">>, Req0, [query_log, table]) ->
    QS = cowboy_req:parse_qs(Req0),
    {Entries, Total} = query_log(QS),
    Page = query_page(QS),
    Sort = query_sort(QS),
    Order = query_order(QS),
    Html = bifrost_view:render_query_log_table(Entries, Total, Page, Sort, Order),
    respond_html(200, Html, Req0);

handle_request(<<"GET">>, Req0, [clients]) ->
    QS = cowboy_req:parse_qs(Req0),
    Clients = case proplists:get_value(<<"ip">>, QS) of
        undefined -> get_clients();
        Ip -> get_client(Ip)
    end,
    respond(200, #{clients => Clients}, Req0);

handle_request(<<"GET">>, Req0, [cluster]) ->
    respond(200, get_cluster(), Req0);

%% Readiness probe. Gates Service membership, i.e. whether this pod receives DNS
%% traffic, so it must answer exactly one question: CAN THIS POD RESOLVE?
%%
%% That means hydration, and ONLY hydration. Until Rust receives reload_complete
%% it SERVFAILs everything, so an unhydrated pod must be pulled from rotation.
%%
%% Postgres is deliberately NOT a readiness condition. DNS resolution is served
%% entirely from Rust's in-memory state (blocklists, allowlist, rewrites, cache)
%% and blocklists survive a DB outage in Mnesia disc_copies. Postgres backs the
%% control plane — query logging, the UI, operational config edits — none of
%% which is needed to answer a query. Gating readiness on the DB meant one
%% Postgres outage marked every pod NotReady simultaneously and took the whole
%% DNS cluster out of its Service: a control-plane failure causing a total
%% data-plane outage. DB health is reported here for observability only.
%% Readiness gates on hydration ONLY. `db` is the pool's last known state, read
%% without touching Postgres: every pod shares it, so a slow query must never be
%% able to mark pods NotReady and pull every DNS IP out of service at once.
handle_request(<<"GET">>, Req0, [health]) ->
    Node = atom_to_binary(node(), utf8),
    DbOk = bifrost_db_pool:is_connected(),
    case bifrost_blocklist_manager:is_hydrated() of
        true ->
            respond(200, #{status => <<"ok">>, node => Node, db => DbOk}, Req0);
        false ->
            respond(503, #{status => <<"unavailable">>, reason => <<"hydrating">>,
                           node => Node, db => DbOk}, Req0)
    end;

%% Liveness/startup probe: is this BEAM answering at all? Deliberately does NOT
%% touch Postgres or hydration state — a DB blip or a slow first fetch must not
%% get the pod killed and restarted, which is what readiness is for.
handle_request(<<"GET">>, Req0, [health_live]) ->
    respond(200, #{status => <<"alive">>, node => atom_to_binary(node(), utf8)}, Req0);

handle_request(<<"POST">>, Req0, [clients_update]) ->
    #{ip := Ip} = cowboy_req:bindings(Req0),
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"name">> := Label} ->
            case parse_ip(Ip) of
                {ok, IpTuple} ->
                    case db_call(equery, "INSERT INTO clients (ip, name, updated_at) VALUES ($1, $2, now()) ON CONFLICT (ip) DO UPDATE SET name = $2, updated_at = now()", [IpTuple, Label]) of
                        {ok, _} -> respond(200, #{ok => true}, Req0);
                        _ -> respond(500, #{error => <<"db error">>}, Req0)
                    end;
                error -> respond(400, #{error => <<"invalid ip">>}, Req0)
            end;
        _ ->
            respond(400, #{error => <<"missing name">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [clients_suspicious]) ->
    #{ip := Ip} = cowboy_req:bindings(Req0),
    QS = cowboy_req:parse_qs(Req0),
    Hours = case proplists:get_value(<<"hours">>, QS) of
        undefined -> 24;
        H -> binary_to_integer(H)
    end,
    Limit = case proplists:get_value(<<"limit">>, QS) of
        undefined -> 50;
        L -> binary_to_integer(L)
    end,
    Enrich = proplists:get_value(<<"enrich">>, QS) =:= <<"true">>,
    %% The IP comes straight off the URL, so parse it here: an inet parameter must
    %% be a tuple, and a malformed one is the caller's mistake, not a 500.
    case parse_ip(Ip) of
        {ok, IpTuple} ->
            Candidates = find_suspicious_domains(IpTuple, Hours, Limit),
            Final = case Enrich of
                true -> enrich_with_rdap(Candidates);
                false -> Candidates
            end,
            respond(200, #{suspicious => Final}, Req0);
        error ->
            respond(400, #{error => <<"invalid ip">>}, Req0)
    end;

handle_request(<<"GET">>, Req0, [rewrites]) ->
    case db_call(query, "SELECT domain, target FROM rewrites") of
        {ok, _, Rows} when is_list(Rows) ->
            respond(200, #{rewrites => format_rewrites(Rows)}, Req0);
        _ ->
            respond(200, #{rewrites => []}, Req0)
    end;

handle_request(<<"POST">>, Req0, [rewrites]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw, <<"target">> := Target} when is_binary(Target), Target =/= <<>> ->
            with_domain(Raw, Req0, fun(Domain) ->
                case db_call(equery, "INSERT INTO rewrites (domain, target) VALUES ($1, $2) ON CONFLICT (domain) DO UPDATE SET target = $2", [Domain, Target]) of
                    {ok, _} ->
                        push_rewrites(),
                        bifrost_mnesia:broadcast_config_reload(),
                        respond(200, #{ok => true}, Req0);
                    _ -> respond(500, #{error => <<"db error">>}, Req0)
                end
            end);
        _ -> respond(400, #{error => <<"missing domain or target">>}, Req0)
    end;

handle_request(<<"DELETE">>, Req0, [rewrites_delete]) ->
    #{domain := Raw} = cowboy_req:bindings(Req0),
    with_domain(Raw, Req0, fun(Domain) ->
        case db_call(equery, "DELETE FROM rewrites WHERE domain = $1", [Domain]) of
            {ok, _} ->
                push_rewrites(),
                bifrost_mnesia:broadcast_config_reload(),
                respond(200, #{ok => true}, Req0);
            _ -> respond(500, #{error => <<"db error">>}, Req0)
        end
    end);

handle_request(<<"GET">>, Req0, [allowlist]) ->
    case db_call(query, "SELECT domain FROM allowlist") of
        {ok, _, Rows} when is_list(Rows) ->
            respond(200, #{domains => [D || {D} <- Rows]}, Req0);
        _ ->
            respond(200, #{domains => []}, Req0)
    end;

handle_request(<<"POST">>, Req0, [allowlist]) ->
    {ok, Body, _} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"domain">> := Raw} ->
            with_domain(Raw, Req0, fun(Domain) -> allow_domain(Domain, Req0) end);
        _ -> respond(400, #{error => <<"missing domain">>}, Req0)
    end;

handle_request(<<"DELETE">>, Req0, [allowlist_delete]) ->
    #{domain := Raw} = cowboy_req:bindings(Req0),
    with_domain(Raw, Req0, fun(Domain) ->
        case db_call(equery, "DELETE FROM allowlist WHERE domain = $1", [Domain]) of
            {ok, _} ->
                push_allowlist(),
                bifrost_mnesia:broadcast_config_reload(),
                respond(200, #{ok => true}, Req0);
            _ -> respond(500, #{error => <<"db error">>}, Req0)
        end
    end);

handle_request(_Method, Req0, _State) ->
    respond(405, #{error => <<"method not allowed">>}, Req0).

%% ── Stats ────────────────────────────────────────────────────

get_stats() ->
    maps:merge(action_counts(), #{
      qps => count_qps(),
      blocked_domains => top_domains(<<"BIFROST_BLOCK">>, 10),
      queried_domains => top_queried_domains(10),
      top_clients => top_clients(10),
      blocklists => get_blocklist_summary(),
      upstreams => get_upstreams()
    }).

%% Every per-action dashboard count in ONE pass over the 90-day window. These
%% were six separate scans, run back to back on the single shared connection on
%% every dashboard load. `upstream_errors` keeps its meaning (any negative or
%% error answer); nxdomain and servfail break it down, since NXDOMAIN is
%% usually a normal answer while SERVFAIL means a resolver problem.
action_counts() ->
    Sql = "SELECT "
          "count(*) FILTER (WHERE action = 'BIFROST_BLOCK'), "
          "count(*) FILTER (WHERE action = 'BIFROST_CACHE'), "
          "count(*) FILTER (WHERE action = 'BIFROST_ALLOW'), "
          "count(*) FILTER (WHERE action = 'BIFROST_RW'), "
          "count(*) FILTER (WHERE action = 'NOERROR'), "
          "count(*) FILTER (WHERE action IN ('SERVFAIL','NXDOMAIN','REFUSED','UNKNOWN')), "
          "count(*) FILTER (WHERE action = 'NXDOMAIN'), "
          "count(*) FILTER (WHERE action = 'SERVFAIL') "
          "FROM query_log WHERE queried_at >= now() - interval '90 days'",
    Keys = [blocked, cached, allowed, rewritten, forwarded, upstream_errors, nxdomain, servfail],
    Values = case db_call(query, Sql) of
        {ok, _, [Row]} -> [to_int(V) || V <- tuple_to_list(Row)];
        _ -> [0 || _ <- Keys]
    end,
    maps:from_list(lists:zip(Keys, Values)).

to_int(V) when is_integer(V) -> V;
to_int(V) when is_binary(V) -> binary_to_integer(V);
to_int(_) -> 0.

count_qps() ->
    Sql = "SELECT COUNT(*) AS n FROM query_log WHERE queried_at >= now() - interval '60 seconds'",
    case db_call(query, Sql) of
        {ok, _, [{N}]} when is_integer(N), N > 0 -> N / 60;
        {ok, _, [{N}]} when is_integer(N) -> 0.0;
        {ok, _, [{N}]} -> binary_to_integer(N) / 60;
        _ -> 0.0
    end.

top_domains(Action, Limit) ->
    case db_call(equery,
        "SELECT domain, COUNT(*) AS n FROM query_log "
        "WHERE action = $1 AND queried_at >= now() - interval '90 days' "
        "GROUP BY domain ORDER BY n DESC LIMIT $2",
        [Action, Limit]) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{domain => D, count => N} || {D, N} <- Rows];
        _ ->
            []
    end.

top_clients(Limit) ->
    %% Effective name mirrors the Clients page: manual label > PTR (cache) > IP.
    %% Read-only join on ptr_cache; warming happens on the Clients page.
    case db_call(equery,
        "SELECT q.client_ip, COUNT(*) AS n, "
        "  COALESCE(NULLIF(c.name, ''), p.name) AS name "
        "FROM query_log q "
        "  LEFT JOIN clients c ON q.client_ip = c.ip "
        "  LEFT JOIN ptr_cache p ON q.client_ip = p.ip AND p.provenance = $2 "
        "WHERE q.queried_at >= now() - interval '90 days' "
        "GROUP BY q.client_ip, c.name, p.name ORDER BY n DESC LIMIT $1",
        [Limit, bifrost_ptr:visible_provenance()]) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{ip => ip_to_binary(Ip), count => N,
               name => case Name of null -> <<>>; _ -> Name end} || {Ip, N, Name} <- Rows];
        _ ->
            []
    end.

top_queried_domains(Limit) ->
    case db_call(equery,
        "SELECT domain, COUNT(*) AS n FROM query_log "
        "WHERE queried_at >= now() - interval '90 days' "
        "GROUP BY domain ORDER BY n DESC LIMIT $1",
        [Limit]) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{domain => D, count => N} || {D, N} <- Rows];
        _ ->
            []
    end.

get_query_trends() ->
    %% 24h of data in 5-minute buckets
    Sql = "SELECT to_char(bucket AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
          "queries, blocked FROM (SELECT "
          "  date_trunc('hour', queried_at) + "
          "  (floor(extract(minute FROM queried_at) / 5) * interval '5 minutes') AS bucket, "
          "  COUNT(*) FILTER (WHERE action NOT IN ('BIFROST_BLOCK')) AS queries, "
          "  COUNT(*) FILTER (WHERE action = 'BIFROST_BLOCK') AS blocked "
          "FROM query_log "
          "WHERE queried_at >= now() - interval '24 hours' "
          "GROUP BY bucket) AS buckets ORDER BY bucket",
    case db_call(query, Sql) of
        {ok, _, Rows} when is_list(Rows) ->
            [#{time => T, queries => Q, blocked => B} || {T, Q, B} <- Rows];
        _ ->
            []
    end.

%% ── Blocklists ───────────────────────────────────────────────

get_blocklists() ->
    Config = case bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end,
    Entries = get_blocklist_entries(Config),
    lists:map(fun format_list/1, Entries).

get_blocklist_entries(Config) ->
    %% Get lists from config file
    FileLists = case maps:find(blocklists, Config) of
        {ok, {default, L}} when is_list(L) -> L;
        {ok, L} when is_list(L) -> L;
        _ -> []
    end,
    %% Get lists from Postgres (UI-added)
    DbLists = case db_call(equery, "SELECT name, url, enabled FROM blocklists WHERE source = 'ui' ORDER BY name", []) of
        {ok, _, Rows} ->
            [[{name, binary_to_list(N)}, {url, binary_to_list(U)}, {enabled, E}] || {N, U, E} <- Rows];
        _ ->
            []
    end,
    %% Merge: DB entries override file entries with same name
    FileNames = [proplists:get_value(name, E, "") || E <- FileLists],
    FilteredDb = [E || E <- DbLists, not lists:member(proplists:get_value(name, E, ""), FileNames)],
    FileLists ++ FilteredDb.

format_list(Entry) ->
    RawName = proplists:get_value(name, Entry, "unknown"),
    Name = list_to_binary(RawName),
    Url  = list_to_binary(proplists:get_value(url, Entry, "")),
    Enabled = proplists:get_value(enabled, Entry, true),
    {DomainCount, ETag} = case bifrost_mnesia:read_cache(RawName) of
        {ok, Domains, E, _} -> {length(Domains), E};
        not_found -> {0, undefined}
    end,
    #{name => Name, url => Url, enabled => Enabled, domains => DomainCount, etag => ETag}.

toggle_blocklist(NameBin) ->
    Name = binary_to_list(NameBin),
    %% Read current state from config and invert
    Config = case bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end,
    Entries = get_blocklist_entries(Config),
    case lists:search(fun(E) -> proplists:get_value(name, E, "") =:= Name end, Entries) of
        false -> {error, <<"not found">>};
        {value, Entry} ->
            Enabled = not proplists:get_value(enabled, Entry, true),
            Url = proplists:get_value(url, Entry, ""),
            %% Persist to Postgres
            case db_call(equery, "INSERT INTO blocklists (name, url, enabled, source) VALUES ($1, $2, $3, 'ui') ON CONFLICT (name) DO UPDATE SET enabled = $3",
                        [NameBin, list_to_binary(Url), Enabled]) of
                {ok, _} ->
                    bifrost_blocklist_manager:refresh_lists(),
                    bifrost_mnesia:broadcast_config_reload(blocklists),
                    ok;
                _ -> {error, <<"db error">>}
            end
    end.

get_blocklist_summary() ->
    Config = case bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end,
    Entries = get_blocklist_entries(Config),
    lists:map(fun(E) ->
        Name = list_to_binary(proplists:get_value(name, E, "unknown")),
        Count = case bifrost_mnesia:read_cache(proplists:get_value(name, E, "unknown")) of
            {ok, D, _, _} -> length(D);
            not_found -> 0
        end,
        #{name => Name, domains => Count}
    end, Entries).

get_builtin_blocklists() ->
    PrivDir = code:priv_dir(bifrost),
    Path = filename:join(PrivDir, "builtin_blocklists.json"),
    case file:read_file(Path) of
        {ok, Data} -> jsx:decode(Data, [return_maps]);
        _ -> #{categories => [], lists => []}
    end.

add_blocklist(Name, Url) when is_binary(Name), is_binary(Url) ->
    %% Insert into DB (will be picked up by config_server on refresh)
    case db_call(equery, 
        "INSERT INTO blocklists (name, url, enabled, source) VALUES ($1, $2, true, 'ui') ON CONFLICT (name) DO NOTHING RETURNING id",
        [Name, Url]) of
        {ok, 1, _, _} ->
            %% Trigger immediate fetch
            bifrost_blocklist_manager:refresh_lists(),
            ok;
        {ok, 0, _, _} ->
            {error, <<"list already exists">>};
        _ ->
            {error, <<"db error">>}
    end.

delete_blocklist(Name) when is_binary(Name) ->
    %% Only delete UI-added lists, not config file lists
    case db_call(equery, "DELETE FROM blocklists WHERE name = $1 AND source = 'ui' RETURNING id", [Name]) of
        {ok, 1, _, _} ->
            %% Clear from Mnesia cache (delete event clears peers' Rust) and
            %% broadcast so every node re-syncs enabled state.
            bifrost_mnesia:delete_cache(binary_to_list(Name)),
            bifrost_blocklist_manager:refresh_lists(),
            bifrost_mnesia:broadcast_config_reload(blocklists),
            ok;
        {ok, 0, _, _} ->
            {error, <<"list not found or is from config file">>};
        _ ->
            {error, <<"db error">>}
    end.

%% ── Blocklist Analysis ───────────────────────────────────────

analyze_blocklists() ->
    %% Load all active blocklists from Mnesia
    Config = case bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end,
    Entries = get_blocklist_entries(Config),
    EnabledEntries = [E || E <- Entries, proplists:get_value(enabled, E, true) =:= true],
    
    %% Get list info - keep domains for overlap analysis
    ListInfo = lists:filtermap(fun(E) ->
        Name = proplists:get_value(name, E, "unknown"),
        case bifrost_mnesia:read_cache(Name) of
            {ok, Domains, _, _} ->
                Count = length(Domains),
                {true, {Name, Count, Domains}};
            _ ->
                false
        end
    end, EnabledEntries),
    
    %% Sort by size (largest first) for smart overlap analysis
    Sorted = lists:sort(fun({_, C1, _}, {_, C2, _}) -> C1 > C2 end, ListInfo),
    
    %% Compute overlaps - only compare smaller lists against larger ones
    Overlaps = compute_smart_overlaps(Sorted),
    
    %% Find redundant lists (>90% covered)
    Redundant = lists:filtermap(fun(O) ->
        case maps:get(pct_of_a_in_b, O) >= 90 of
            true -> {true, #{
                redundant_list => maps:get(list_a, O),
                covered_by => maps:get(list_b, O),
                coverage_pct => maps:get(pct_of_a_in_b, O),
                redundant_domains => maps:get(a_domains, O),
                covering_domains => maps:get(b_domains, O)
            }};
            false -> false
        end
    end, Overlaps),
    
    TotalWithDupes = lists:sum([C || {_, C, _} <- ListInfo]),
    
    #{
        lists => [#{name => list_to_binary(N), domains => C} || {N, C, _} <- Sorted],
        total_with_dupes => TotalWithDupes,
        overlaps => [O || O <- Overlaps, maps:get(pct_of_a_in_b, O) >= 20],
        redundant => Redundant
    }.

compute_smart_overlaps(SortedLists) ->
    %% Compare each list against larger lists only (sorted largest-first)
    compute_smart_overlaps(SortedLists, [], []).

compute_smart_overlaps([], _Larger, Acc) ->
    Acc;
compute_smart_overlaps([{NameA, CountA, DomainsA} | Rest], Larger, Acc) ->
    %% Skip overlap analysis for very large lists (too slow)
    case CountA > 100000 of
        true ->
            compute_smart_overlaps(Rest, [{NameA, CountA, DomainsA} | Larger], Acc);
        false ->
            %% Compare A against each larger list (that's not too large)
            SmallLarger = [{N, C, D} || {N, C, D} <- Larger, C < 100000],
            NewOverlaps = lists:filtermap(fun({NameB, CountB, DomainsB}) ->
                %% Build set from B, check A domains against it
                SetB = sets:from_list(DomainsB),
                %% Sample for moderately large lists
                {SampleA, SampleSize} = if
                    CountA > 10000 -> {lists:sublist(DomainsA, 2000), 2000};
                    true -> {DomainsA, CountA}
                end,
                Matches = length([D || D <- SampleA, sets:is_element(D, SetB)]),
                Overlap = round(Matches * CountA / max(1, SampleSize)),
                Pct = case CountA of 0 -> 0; _ -> round(Overlap / CountA * 100) end,
                case Pct >= 10 of
                    true ->
                        {true, #{
                            list_a => list_to_binary(NameA),
                            list_b => list_to_binary(NameB),
                            overlap_count => Overlap,
                            pct_of_a_in_b => Pct,
                            a_domains => CountA,
                            b_domains => CountB
                        }};
                    false ->
                        false
                end
            end, SmallLarger),
            compute_smart_overlaps(Rest, [{NameA, CountA, DomainsA} | Larger], NewOverlaps ++ Acc)
    end.

%% ── Query Log ────────────────────────────────────────────────

query_log(QS) ->
    Search = proplists:get_value(<<"search">>, QS),
    Action = proplists:get_value(<<"action">>, QS),
    Page = query_page(QS),
    Sort = query_sort(QS),
    Order = query_order(QS),
    Limit = 50,
    Offset = (Page - 1) * Limit,
    {Where0, Params} = build_where(Search, Action, 1),
    Where = case query_range(QS) of
        all -> Where0;
        Interval ->
            Clause = "queried_at >= now() - interval '" ++ Interval ++ "'",
            case Where0 of "" -> "WHERE " ++ Clause; _ -> Where0 ++ " AND " ++ Clause end
    end,
    OrderBy = build_order_by(Sort, Order),
    CountSql = "SELECT COUNT(*) FROM query_log " ++ Where,
    Total = case db_call(equery, CountSql, Params) of
        {ok, _, [{N}]} when is_integer(N) -> N;
        {ok, _, [{N}]} -> binary_to_integer(N);
        _ -> 0
    end,
    DataSql = "SELECT ql.id, ql.client_ip, ql.domain, ql.qtype, ql.action, ql.client_rcode, ql.ede_code, ql.list_id, ql.latency_us, ql.queried_at, COALESCE(NULLIF(c.name, ''), p.name, '') AS client_name, ql.response_records "
              "FROM query_log ql "
              "  LEFT JOIN clients c ON ql.client_ip = c.ip "
              "  LEFT JOIN ptr_cache p ON ql.client_ip = p.ip AND p.provenance = $" ++
              integer_to_list(length(Params) + 3) ++ " "
              ++ Where ++ " ORDER BY " ++ OrderBy ++ " LIMIT $" ++ integer_to_list(length(Params) + 1) ++
              " OFFSET $" ++ integer_to_list(length(Params) + 2),
    Entries = case db_call(equery, DataSql, Params ++ [Limit, Offset, bifrost_ptr:visible_provenance()]) of
        {ok, _, Rows} when is_list(Rows) ->
            lists:map(fun format_log_entry/1, Rows);
        _ ->
            []
    end,
    {Entries, Total}.

%% The time window is a whitelist mapped to literal intervals, never caller text.
%% Default matches the dashboard's 90-day totals so the pages agree.
query_range(QS) ->
    case proplists:get_value(<<"range">>, QS) of
        <<"1h">> -> "1 hour";
        <<"24h">> -> "24 hours";
        <<"7d">> -> "7 days";
        <<"30d">> -> "30 days";
        <<"all">> -> all;
        _ -> ?STATS_WINDOW
    end.

query_page(QS) ->
    case catch binary_to_integer(proplists:get_value(<<"page">>, QS, <<"1">>)) of
        N when is_integer(N), N > 0, N =< 100000 -> N;
        _ -> 1
    end.

query_sort(QS) ->
    case proplists:get_value(<<"sort">>, QS, <<"time">>) of
        <<"time">> -> <<"time">>;
        <<"domain">> -> <<"domain">>;
        <<"client">> -> <<"client">>;
        <<"action">> -> <<"action">>;
        _ -> <<"time">>
    end.

query_order(QS) ->
    case proplists:get_value(<<"order">>, QS, <<"desc">>) of
        <<"asc">> -> <<"asc">>;
        _ -> <<"desc">>
    end.

build_order_by(<<"time">>,   <<"asc">>)  -> "ql.queried_at ASC";
build_order_by(<<"time">>,   _)          -> "ql.queried_at DESC";
build_order_by(<<"domain">>, <<"desc">>) -> "ql.domain DESC";
build_order_by(<<"domain">>, _)          -> "ql.domain ASC";
build_order_by(<<"client">>, <<"desc">>) -> "ql.client_ip DESC";
build_order_by(<<"client">>, _)          -> "ql.client_ip ASC";
build_order_by(<<"action">>, <<"desc">>) -> "ql.action DESC";
build_order_by(<<"action">>, _)          -> "ql.action ASC";
build_order_by(_, _)                     -> "ql.queried_at DESC".

%% Only Action and Search are ever filtered on. This used to route through a
%% build_where_inner/5 carrying per-column `client_ip = $N` and `domain LIKE $N`
%% filters that no caller ever populated — both always `undefined`. The client one
%% was also a latent copy of the inet-parameter crash fixed in
%% find_suspicious_domains/3: a bare binary bound to an inet column kills the
%% epgsql socket and takes the pool with it. Search compares
%% `client_ip::text LIKE`, which is safe by construction AND is what makes a
%% partial IP ("192.168.") match at all.
build_where(Search, Action, _N) ->
    {C0, P0} = case Action of
        A when A =:= undefined; A =:= <<>> -> {[], []};
        _ -> {["action = $1"], [Action]}
    end,
    {Clauses, Params} = case Search of
        S when S =:= undefined; S =:= <<>> -> {C0, P0};
        _ ->
            N1 = length(P0) + 1,
            N2 = length(P0) + 2,
            LikeVal = <<"%", Search/binary, "%">>,
            {C0 ++ ["(domain LIKE $" ++ integer_to_list(N1)
                    ++ " OR client_ip::text LIKE $" ++ integer_to_list(N2) ++ ")"],
             P0 ++ [LikeVal, LikeVal]}
    end,
    case Clauses of
        [] -> {"", []};
        _  -> {"WHERE " ++ lists:join(" AND ", Clauses), Params}
    end.

format_log_entry({Id, ClientIp, Domain, Qtype, Action, ClientRcode, EdeCode, ListId, Latency, QueriedAt, ClientName, ResponseRecords}) ->
    #{id => Id, client_ip => ip_to_binary(ClientIp), domain => Domain, qtype => Qtype,
      action => Action, client_rcode => ClientRcode,
      ede_code => EdeCode, list_id => ListId, latency_us => Latency,
      queried_at => QueriedAt, client_name => ClientName,
      response_records => parse_response_records(ResponseRecords)}.

parse_response_records(null) -> [];
parse_response_records(undefined) -> [];
parse_response_records(<<>>) -> [];
parse_response_records(Json) when is_binary(Json) ->
    case jsx:decode(Json, [return_maps]) of
        Records when is_list(Records) -> Records;
        _ -> []
    end;
parse_response_records(_) -> [].
%% ── Clients ──────────────────────────────────────────────────

get_clients() ->
    case db_call(equery,
        "SELECT q.client_ip, c.name, "
        "  COUNT(*) FILTER (WHERE q.action = 'BIFROST_BLOCK') AS blocked, "
        "  COUNT(*) AS total, " ?LAST_SEEN
        "FROM query_log q LEFT JOIN clients c ON c.ip = q.client_ip "
        "WHERE q.queried_at >= now() - interval '" ?STATS_WINDOW "' "
        "GROUP BY q.client_ip, c.name ORDER BY total DESC LIMIT 200", []) of
        {ok, _, Rows} when is_list(Rows) ->
            [client_entry(Ip, Name, B, T, L) || {Ip, Name, B, T, L} <- Rows];
        _ ->
            []
    end.

%% Exact-client lookup supports dashboard/query drill-ins even when the client
%% is outside the top-200 overview. Parse URL data before binding it as inet.
get_client(IpBin) ->
    case parse_ip(IpBin) of
        {ok, Ip} ->
            case db_call(equery,
                "SELECT q.client_ip, c.name, COUNT(*) FILTER (WHERE q.action = 'BIFROST_BLOCK') AS blocked, COUNT(*) AS total, " ?LAST_SEEN "FROM query_log q LEFT JOIN clients c ON c.ip = q.client_ip WHERE q.client_ip = $1 AND q.queried_at >= now() - interval '" ?STATS_WINDOW "' GROUP BY q.client_ip, c.name", [Ip]) of
                {ok, _, Rows} when is_list(Rows) ->
                    [client_entry(ClientIp, Name, Blocked, Total, L) || {ClientIp, Name, Blocked, Total, L} <- Rows];
                _ -> []
            end;
        error -> []
    end.

%% Effective client name precedence: manual label > PTR (auto) > raw IP.
%% `name_source` lets the UI grey/label auto-resolved PTR names.
client_entry(Ip, Label, Blocked, Total, LastSeen) ->
    IpBin = ip_to_binary(Ip),
    HasLabel = is_binary(Label) andalso Label =/= <<>>,
    {Name, Source} = case HasLabel of
        true -> {Label, <<"label">>};
        false ->
            case bifrost_ptr:name_for(IpBin, <<>>) of
                undefined -> {null, <<"ip">>};
                Ptr -> {Ptr, <<"ptr">>}
            end
    end,
    #{ip => IpBin, name => Name, name_source => Source,
      label => case HasLabel of true -> Label; false -> null end,
        blocked => Blocked, total => Total, last_seen => LastSeen}.

%% ── Cluster ──────────────────────────────────────────────────
%% Cluster topology + health for the UI. All query-log/metric data is summed
%% from the shared Postgres (node-agnostic); this endpoint exposes the things
%% that ARE per-node: who's connected, who's healthy, and how each recurring
%% job is coordinated across nodes.
%%
%% The three jobs use deliberately different coordination, because the work has
%% different shapes — see cluster_jobs/1.
get_cluster() ->
    This = atom_to_binary(node(), utf8),
    Members = [node() | nodes()],
    LeaderNode = singleton_node(bifrost_ptr_warmer_leader),
    MnesiaNodes = [atom_to_binary(N, utf8) || N <- mnesia:system_info(running_db_nodes)],
    Nodes = [node_info(N, LeaderNode) || N <- lists:sort(Members)],
    #{this_node => This,
      node_count => length(Members),
      db_shared => true,
      db_ok => db_ok(),
      mnesia_nodes => MnesiaNodes,
      leader => case LeaderNode of undefined -> null; L -> atom_to_binary(L, utf8) end,
      jobs => cluster_jobs(),
      nodes => Nodes}.

%% Two coordination shapes, deliberately different because the work differs:
%%
%%   cluster singletons  one indivisible sweep with no shard key, where running
%%                       it on N nodes just multiplies load on a shared resource
%%                       (one gateway resolver, the shared query_log, third-party
%%                       RDAP). Enumerated from bifrost_cluster:singleton_jobs/0
%%                       so a newly added singleton appears here automatically
%%                       instead of being silently missing from the dashboard.
%%
%%   blocklist_refresh   N independent lists, each its own HTTP fetch + parse, so
%%                       a per-list lock lets different nodes fetch different
%%                       lists concurrently. Not a singleton, hence hand-rolled.
cluster_jobs() ->
    [singleton_job(Name, GlobalName, Interval, Coordination)
     || {Name, GlobalName, Interval, Coordination} <- bifrost_cluster:singleton_jobs()]
    ++ [blocklist_refresh_job()].

%% Holding the global name proves the owning process is alive, so "assigned" is
%% the health signal. When it is unassigned the interval tells the operator
%% whether that is simply "hasn't ticked since boot" or genuinely wrong — without
%% it, a job with a 5 min period looks broken for 5 min after every restart.
singleton_job(Name, GlobalName, Interval, Coordination) ->
    Node = singleton_node(GlobalName),
    #{name => Name,
      scope => <<"cluster singleton">>,
      coordination => Coordination,
      interval_seconds => Interval,
      status => case Node of
                    undefined ->
                        iolist_to_binary([<<"unassigned (ticks every ">>,
                                          human_interval(Interval), <<")">>]);
                    N -> atom_to_binary(N, utf8)
                end,
      leader => case Node of undefined -> null; N2 -> atom_to_binary(N2, utf8) end}.

human_interval(S) when S < 60 -> [integer_to_binary(S), <<"s">>];
human_interval(S) when S < 3600 -> [integer_to_binary(S div 60), <<"m">>];
human_interval(S) -> [integer_to_binary(S div 3600), <<"h">>].

%% Freshness is read with a select that projects ONLY the timestamp. A
%% dirty_read here would copy every domain of every list (millions of binaries)
%% into this process on every dashboard poll.
blocklist_refresh_job() ->
    Now = erlang:system_time(second),
    Ages =
        try
            [Now - F || F <- mnesia:dirty_select(
                                blocklist_cache,
                                [{{blocklist_cache, '_', '_', '_', '$1'}, [], ['$1']}])]
        catch _:_ -> []
        end,
    Total = length(Ages),
    Stale = length([A || A <- Ages, A >= 24 * 60 * 60]),
    Status = case Total of
                 0 -> <<"no lists cached">>;
                 _ -> iolist_to_binary([integer_to_binary(Total), <<" lists, ">>,
                                        integer_to_binary(Stale), <<" stale">>])
             end,
    #{name => <<"blocklist_refresh">>,
      scope => <<"per-list lock">>,
      coordination => <<"any node may fetch; one node per list via a cluster-wide lock">>,
      status => Status,
      lists => Total,
      stale => Stale,
      oldest_age_seconds => case Ages of [] -> null; _ -> lists:max(Ages) end,
      leader => null}.

%% node() is always up (it's us). Peers count as up while connected — the BEAM
%% drops them from nodes() the instant distribution sees them go.
node_info(N, LeaderNode) ->
    Up = (N =:= node()) orelse lists:member(N, nodes()),
    #{name => atom_to_binary(N, utf8),
      self => N =:= node(),
      status => case Up of true -> <<"up">>; false -> <<"down">> end,
      leader => N =:= LeaderNode}.

%% Node that owns a `global` singleton name, or undefined if unheld.
singleton_node(Name) ->
    case global:whereis_name(Name) of
        undefined -> undefined;
        Pid -> node(Pid)
    end.

db_ok() ->
    case db_call(query, "SELECT 1") of
        {ok, _, _} -> true;
        _ -> false
    end.

get_threat_settings() ->
    case db_call(query, "SELECT key, value FROM settings WHERE key LIKE 'auto_block%'") of
        {ok, _, Rows} when is_list(Rows) ->
            maps:from_list([{K, V} || {K, V} <- Rows]);
        _ ->
            #{}
    end.

get_threats() ->
    case db_call(query,
        "SELECT domain, score, reasons, hits, age_days, "
        "  to_char(first_seen, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
        "FROM suspicious_candidates WHERE status = 'pending' "
        "ORDER BY score DESC, hits DESC LIMIT 200") of
        {ok, _, Rows} when is_list(Rows) ->
            [#{domain => D, score => S,
               reasons => parse_reasons(R),
               hits => H, age_days => Age, first_seen => FS}
             || {D, S, R, H, Age, FS} <- Rows];
        _ ->
            []
    end.

parse_reasons(null) -> [];
parse_reasons(undefined) -> [];
parse_reasons(Bin) when is_binary(Bin) ->
    case catch jsx:decode(Bin, [return_maps]) of
        L when is_list(L) -> L;
        _ -> []
    end;
parse_reasons(_) -> [].

%% Push operational config to the local Rust. Each read falls back to the
%% last-known Mnesia snapshot when Postgres is down or hung (bifrost_opconfig),
%% so a pod hydrating during an outage keeps its rewrites, allowlist and blocks.
push_rewrites() ->
    push(rewrites, {"SELECT domain, target FROM rewrites",
                    fun(Rows) -> [#{domain => D, target => T} || {D, T} <- Rows] end},
         fun(Entries) -> [#{type => <<"load_rewrites">>, entries => Entries}] end).

push_allowlist() ->
    push(allowlist, {"SELECT domain FROM allowlist", fun(Rows) -> [D || {D} <- Rows] end},
         fun(Domains) -> [#{type => <<"load_allowlist">>, entries => Domains}] end).

%% The reserved `manual` list is rebuilt off to the side and swapped in whole,
%% so a re-push never leaves a window where manually blocked names resolve.
push_manual_blocks() ->
    push(manual_blocks, {"SELECT domain FROM manual_blocks", fun(Rows) -> [D || {D} <- Rows] end},
         fun(Domains) ->
             [#{type => <<"begin_blocklist">>, list_id => <<"manual">>},
              #{type => <<"load_blocklist">>, list_id => <<"manual">>, entries => Domains},
              #{type => <<"commit_blocklist">>, list_id => <<"manual">>}]
         end).

push_client_blocks() ->
    push(client_blocks, {"SELECT host(client_ip), domain FROM client_blocks",
                         fun(Rows) -> [#{client_ip => Ip, domain => D} || {Ip, D} <- Rows] end},
         fun(Entries) -> [#{type => <<"load_client_blocks">>, entries => Entries}] end).

push(Key, Query, ToMessages) ->
    case bifrost_opconfig:read(Key, Query) of
        {ok, Value} ->
            [_ = (catch bifrost_socket_server:send_message(M)) || M <- ToMessages(Value)],
            ok;
        error ->
            logger:error("no ~p available from Postgres or snapshot; not pushed", [Key]),
            ok
    end.

get_upstreams() ->
    [element(2, E) || E <- bifrost_upstream_monitor:get_all()].

ip_to_binary(Ip) when is_tuple(Ip) ->
    list_to_binary(inet:ntoa(Ip));
ip_to_binary(Ip) ->
    Ip.

%% Parse a client IP binary to an inet tuple for epgsql (its binary protocol
%% requires inet params as tuples, not strings).
parse_ip(Bin) when is_binary(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, Tuple} -> {ok, Tuple};
        _ -> error
    end;
parse_ip(_) -> error.

%% Every rule endpoint takes the domain through bifrost_domain:normalize/1, so
%% rows are stored in one canonical spelling and the query log's as-queried
%% names (`Ads.Example.COM.`) match what was stored.
with_domain(Raw, Req0, Fun) ->
    case bifrost_domain:normalize(Raw) of
        {ok, Domain} -> Fun(Domain);
        error -> respond(400, #{error => <<"invalid domain">>}, Req0)
    end.

%% Block and allow are mutually exclusive. Each moves the domain between the two
%% tables in ONE statement (data-modifying CTE), so a failure can never leave it
%% in both lists or in neither.
block_domain(Domain, Req0) ->
    Sql = "WITH unallowed AS (DELETE FROM allowlist WHERE domain = $1) "
          "INSERT INTO manual_blocks (domain) VALUES ($1) ON CONFLICT DO NOTHING",
    case db_call(equery, Sql, [Domain]) of
        {ok, _} ->
            push_allowlist(),
            push_manual_blocks(),
            bifrost_mnesia:broadcast_config_reload(),
            bifrost_mnesia:broadcast_evict(Domain),
            respond(200, #{ok => true, domain => Domain}, Req0);
        _ -> respond(500, #{error => <<"db error">>}, Req0)
    end.

allow_domain(Domain, Req0) ->
    Sql = "WITH unblocked AS (DELETE FROM manual_blocks WHERE domain = $1) "
          "INSERT INTO allowlist (domain) VALUES ($1) ON CONFLICT DO NOTHING",
    case db_call(equery, Sql, [Domain]) of
        {ok, _} ->
            push_allowlist(),
            push_manual_blocks(),
            bifrost_mnesia:broadcast_config_reload(),
            bifrost_mnesia:broadcast_evict(Domain),
            respond(200, #{ok => true, domain => Domain}, Req0);
        _ -> respond(500, #{error => <<"db error">>}, Req0)
    end.

format_rewrites(Rows) ->
    [#{domain => D, target => T} || {D, T} <- Rows].

%% ── Suspicious domain detection ──────────────────────────────

%% ClientIp MUST be a parsed inet tuple, not a binary. epgsql binds $1 with the
%% inet codec (the `::inet` cast tells Postgres the parameter type), and that codec
%% function_clauses on a binary — which kills the epgsql socket process and, since
%% it is linked, takes bifrost_db_pool down with it. The caller parses and rejects
%% a malformed IP before we get here.
%% The is_tuple guard is load-bearing: with the pool now catching bad parameters,
%% a binary here would quietly yield {error,_} and an EMPTY candidate list — a
%% silent wrong answer. Failing loudly is the better trade.
find_suspicious_domains(ClientIpTuple, Hours, Limit) when is_tuple(ClientIpTuple) ->
    %% Get allowed domains for this client in the time window
    Sql = "SELECT DISTINCT domain, COUNT(*) as hits
           FROM query_log
           WHERE client_ip = $1::inet
             AND queried_at > now() - ($2 || ' hours')::interval
             AND action NOT IN ('BIFROST_BLOCK', 'BIFROST_CACHE')
           GROUP BY domain
           ORDER BY hits DESC
           LIMIT 500",
    case db_call(equery, Sql, [ClientIpTuple, integer_to_list(Hours)]) of
        {ok, _, Rows} ->
            Scored = lists:filtermap(fun({Domain, Hits}) ->
                Score = score_domain(Domain, Hits),
                case Score > 0 of
                    true -> {true, #{domain => Domain, score => Score, hits => Hits,
                                     reasons => score_reasons(Domain, Hits)}};
                    false -> false
                end
            end, Rows),
            Sorted = lists:sort(fun(A, B) ->
                maps:get(score, A) >= maps:get(score, B)
            end, Scored),
            lists:sublist(Sorted, Limit);
        _ -> []
    end.

score_domain(Domain, Hits) ->
    score_numbered_subdomain(Domain) +
    score_hyphenated_generic(Domain) +
    score_burst_hits(Hits) +
    score_suspicious_tld(Domain) +
    score_short_random(Domain) +
    score_entropy(Domain) +
    score_subdomain_depth(Domain) +
    score_long_domain(Domain).

%% Numbered subdomain pattern: 1.example.com, 7.stg.example.com
score_numbered_subdomain(Domain) ->
    case re:run(Domain, "^[0-9]+\\.", [{capture, none}]) of
        match -> 3;
        nomatch ->
            case re:run(Domain, "\\.[0-9]+\\.", [{capture, none}]) of
                match -> 2;
                nomatch -> 0
            end
    end.

%% Generic hyphenated names: content-loader, error-report, html-load
score_hyphenated_generic(Domain) ->
    Generics = [<<"content-">>, <<"error-">>, <<"-load">>, <<"-loader">>,
                <<"-report">>, <<"-track">>, <<"-sync">>, <<"-cdn">>],
    case lists:any(fun(P) -> binary:match(Domain, P) =/= nomatch end, Generics) of
        true -> 2;
        false -> 0
    end.

%% Burst of hits in short window suggests ad SDK
score_burst_hits(Hits) when Hits >= 10 -> 2;
score_burst_hits(Hits) when Hits >= 5 -> 1;
score_burst_hits(_) -> 0.

%% Suspicious TLDs commonly used for throwaway ad domains
score_suspicious_tld(Domain) ->
    Suspicious = [<<".xyz">>, <<".top">>, <<".club">>, <<".work">>,
                  <<".site">>, <<".online">>, <<".click">>, <<".link">>],
    case lists:any(fun(T) ->
        byte_size(Domain) > byte_size(T) andalso
        binary:part(Domain, byte_size(Domain) - byte_size(T), byte_size(T)) =:= T
    end, Suspicious) of
        true -> 1;
        false -> 0
    end.

%% Short random-looking domain (like "duhrawhide")
score_short_random(Domain) ->
    %% Extract base domain (last two parts)
    Parts = binary:split(Domain, <<".">>, [global]),
    case Parts of
        [Base, _Tld] ->
            %% No vowels or weird consonant clusters = suspicious
            case re:run(Base, "^[bcdfghjklmnpqrstvwxz]{4,}", [{capture, none}, caseless]) of
                match -> 2;
                nomatch -> 0
            end;
        _ -> 0
    end.

%% Shannon entropy of domain name — random strings have high entropy
score_entropy(Domain) ->
    %% Strip TLD for entropy calc
    Parts = binary:split(Domain, <<".">>, [global]),
    Name = case Parts of
        [H | _] -> H;
        _ -> Domain
    end,
    Entropy = shannon_entropy(Name),
    if
        Entropy > 4.0 -> 2;  %% High entropy = likely random
        Entropy > 3.5 -> 1;
        true -> 0
    end.

shannon_entropy(Bin) when byte_size(Bin) == 0 -> 0.0;
shannon_entropy(Bin) ->
    Len = byte_size(Bin),
    Freqs = lists:foldl(fun(C, Acc) ->
        maps:update_with(C, fun(V) -> V + 1 end, 1, Acc)
    end, #{}, binary_to_list(Bin)),
    maps:fold(fun(_Char, Count, Acc) ->
        P = Count / Len,
        Acc - P * math:log2(P)
    end, 0.0, Freqs).

%% Deep subdomain nesting: a.b.c.d.example.com
score_subdomain_depth(Domain) ->
    Parts = binary:split(Domain, <<".">>, [global]),
    Depth = length(Parts),
    if
        Depth >= 5 -> 2;
        Depth >= 4 -> 1;
        true -> 0
    end.

%% Very long domain names
score_long_domain(Domain) ->
    Len = byte_size(Domain),
    if
        Len > 50 -> 2;
        Len > 35 -> 1;
        true -> 0
    end.

score_reasons(Domain, Hits) ->
    R1 = case score_numbered_subdomain(Domain) > 0 of
        true -> [<<"numbered_subdomain">>]; false -> []
    end,
    R2 = case score_hyphenated_generic(Domain) > 0 of
        true -> [<<"hyphenated_generic">>]; false -> []
    end,
    R3 = case score_burst_hits(Hits) > 0 of
        true -> [<<"burst_hits">>]; false -> []
    end,
    R4 = case score_suspicious_tld(Domain) > 0 of
        true -> [<<"suspicious_tld">>]; false -> []
    end,
    R5 = case score_short_random(Domain) > 0 of
        true -> [<<"random_name">>]; false -> []
    end,
    R6 = case score_entropy(Domain) > 0 of
        true -> [<<"high_entropy">>]; false -> []
    end,
    R7 = case score_subdomain_depth(Domain) > 0 of
        true -> [<<"deep_subdomains">>]; false -> []
    end,
    R8 = case score_long_domain(Domain) > 0 of
        true -> [<<"long_domain">>]; false -> []
    end,
    R1 ++ R2 ++ R3 ++ R4 ++ R5 ++ R6 ++ R7 ++ R8.


%% ── RDAP enrichment ──────────────────────────────────────────

enrich_with_rdap(Candidates) ->
    %% The cap is now about page latency on a cold cache only — a warm cache
    %% costs one indexed SELECT per domain, so this could be raised safely.
    {ToEnrich, Rest} = lists:split(min(10, length(Candidates)), Candidates),
    Enriched = [enrich_one(C) || C <- ToEnrich],
    %% Re-sort after enrichment
    lists:sort(fun(A, B) ->
        maps:get(score, A) >= maps:get(score, B)
    end, Enriched ++ Rest).

enrich_one(C) ->
    Data = rdap_cached(maps:get(domain, C)),
    C#{score => maps:get(score, C) + score_rdap(Data),
       reasons => maps:get(reasons, C) ++ rdap_reasons(Data),
       rdap => Data}.

%% Read-through cache over rdap_lookup/1, shared with bifrost_domain_analyzer so
%% one registry request serves the periodic scan AND every page load.
%%
%% Keyed on the REGISTRABLE base domain, because that is what RDAP describes:
%% every subdomain variant of one registration (1.ads.example.com,
%% 2.ads.example.com, ...) collapses onto a single entry, which is exactly the
%% shape of the throwaway domains this scan looks for.
%%
%% Failures are cached too. Most TLDs have no rdap_server/1 entry at all, and a
%% 404 or timeout is just as repeatable as a hit — not storing those meant an
%% unsupported TLD was re-requested on every single scan and page load.
%%
%% Always returns the same four-key shape, so a cache hit and a fresh fetch are
%% indistinguishable to callers. Unknown fields are `undefined`; score_rdap/1 and
%% rdap_reasons/1 treat those as "no signal".
-spec rdap_cached(binary()) -> #{atom() => term()}.
rdap_cached(Domain) ->
    Base = extract_base_domain(Domain),
    case db_call(equery, "SELECT age_days, has_transfer_lock, pending_delete, "
                         "privacy_protected FROM rdap_cache WHERE domain = $1", [Base]) of
        {ok, _, [{Age, Lock, Del, Priv}]} ->
            #{age_days => denull(Age), has_transfer_lock => denull(Lock),
              pending_delete => denull(Del), privacy_protected => denull(Priv)};
        _ ->
            Fetched = case rdap_lookup(Base) of
                          {ok, D} -> D;
                          {error, _} -> #{}
                      end,
            Fields = #{age_days => maps:get(age_days, Fetched, undefined),
                       has_transfer_lock => maps:get(has_transfer_lock, Fetched, undefined),
                       pending_delete => maps:get(pending_delete, Fetched, undefined),
                       privacy_protected => maps:get(privacy_protected, Fetched, undefined)},
            store_rdap(Base, Fields),
            Fields
    end.

%% Registration facts are immutable, so a stored row is never refreshed: first
%% writer wins and a concurrent scan on another node is a harmless no-op.
store_rdap(Base, F) ->
    _ = db_call(equery,
        "INSERT INTO rdap_cache (domain, age_days, has_transfer_lock, pending_delete, "
        "privacy_protected) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (domain) DO NOTHING",
        [Base, maps:get(age_days, F), maps:get(has_transfer_lock, F),
         maps:get(pending_delete, F), maps:get(privacy_protected, F)]),
    ok.

%% epgsql yields `null` for SQL NULL; the rest of the module speaks `undefined`.
denull(null) -> undefined;
denull(V) -> V.

rdap_lookup(Domain) ->
    %% Extract base domain (registrable domain, not subdomain)
    BaseDomain = extract_base_domain(Domain),
    Tld = extract_tld(BaseDomain),
    case rdap_server(Tld) of
        undefined -> {error, no_rdap_server};
        Server ->
            Url = Server ++ "/domain/" ++ binary_to_list(BaseDomain),
            case httpc:request(get, {Url, [{"Accept", "application/rdap+json"}]},
                               [{timeout, 5000}, {connect_timeout, 3000}], []) of
                {ok, {{_, 200, _}, _, Body}} ->
                    try
                        Data = jsx:decode(list_to_binary(Body), [return_maps]),
                        {ok, parse_rdap(Data)}
                    catch _:_ -> {error, parse_failed}
                    end;
                {ok, {{_, 404, _}, _, _}} -> {error, not_found};
                _ -> {error, request_failed}
            end
    end.

extract_base_domain(Domain) ->
    %% Simple extraction: take last two parts (or three for .co.uk etc)
    Parts = binary:split(Domain, <<".">>, [global]),
    case Parts of
        [_] -> Domain;
        [_, _] -> Domain;
        _ -> iolist_to_binary(lists:join(<<".">>, lists:nthtail(length(Parts) - 2, Parts)))
    end.

extract_tld(Domain) ->
    Parts = binary:split(Domain, <<".">>, [global]),
    lists:last(Parts).

rdap_server(<<"com">>) -> "https://rdap.verisign.com/com/v1";
rdap_server(<<"net">>) -> "https://rdap.verisign.com/net/v1";
rdap_server(<<"org">>) -> "https://rdap.publicinterestregistry.org/rdap";
rdap_server(<<"io">>)  -> "https://rdap.nic.io";
rdap_server(<<"xyz">>) -> "https://rdap.nic.xyz";
rdap_server(<<"top">>) -> "https://rdap.nic.top";
rdap_server(<<"site">>) -> "https://rdap.nic.site";
rdap_server(<<"online">>) -> "https://rdap.nic.online";
rdap_server(<<"click">>) -> "https://rdap.nic.click";
rdap_server(<<"link">>) -> "https://rdap.nic.link";
rdap_server(<<"club">>) -> "https://rdap.nic.club";
rdap_server(<<"work">>) -> "https://rdap.nic.work";
rdap_server(_) -> undefined.

parse_rdap(Data) ->
    %% Extract registration date
    Events = maps:get(<<"events">>, Data, []),
    RegDate = find_event_date(Events, <<"registration">>),
    
    %% Extract status codes
    Statuses = maps:get(<<"status">>, Data, []),
    
    %% Check for redacted/privacy registrant
    Entities = maps:get(<<"entities">>, Data, []),
    PrivacyProtected = is_privacy_protected(Entities),
    
    #{
        registration_date => RegDate,
        age_days => calculate_age_days(RegDate),
        statuses => Statuses,
        privacy_protected => PrivacyProtected,
        has_transfer_lock => lists:member(<<"client transfer prohibited">>, Statuses),
        has_delete_lock => lists:member(<<"client delete prohibited">>, Statuses),
        has_update_lock => lists:member(<<"client update prohibited">>, Statuses),
        pending_delete => lists:member(<<"pending delete">>, Statuses)
    }.

find_event_date([], _Action) -> undefined;
find_event_date([Event | Rest], Action) ->
    case maps:get(<<"eventAction">>, Event, undefined) of
        Action -> maps:get(<<"eventDate">>, Event, undefined);
        _ -> find_event_date(Rest, Action)
    end.

calculate_age_days(undefined) -> undefined;
calculate_age_days(DateBin) ->
    try
        %% Parse ISO 8601 date like "2024-01-15T00:00:00Z"
        <<Y:4/binary, "-", M:2/binary, "-", D:2/binary, _/binary>> = DateBin,
        RegDate = {binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)},
        Today = date(),
        calendar:date_to_gregorian_days(Today) - calendar:date_to_gregorian_days(RegDate)
    catch _:_ -> undefined
    end.

is_privacy_protected([]) -> false;
is_privacy_protected([Entity | Rest]) ->
    %% Check if registrant has redacted/privacy markers
    Roles = maps:get(<<"roles">>, Entity, []),
    case lists:member(<<"registrant">>, Roles) of
        true ->
            VCard = maps:get(<<"vcardArray">>, Entity, []),
            case is_redacted_vcard(VCard) of
                true -> true;
                false -> is_privacy_protected(Rest)
            end;
        false ->
            is_privacy_protected(Rest)
    end.

is_redacted_vcard([]) -> false;
is_redacted_vcard([<<"vcard">>, Fields]) ->
    %% Look for privacy indicators in vcard fields
    FieldsFlat = lists:flatten(Fields),
    lists:any(fun
        (B) when is_binary(B) ->
            LowerB = string:lowercase(binary_to_list(B)),
            lists:any(fun(P) -> string:find(LowerB, P) =/= nomatch end,
                      ["redacted", "privacy", "private", "protected", "withheld", "data protected"]);
        (_) -> false
    end, FieldsFlat);
is_redacted_vcard(_) -> false.

%% Not every RDAP field earns score. A signal only scores if it DISCRIMINATES —
%% one that fires on most of the internet is a constant offset, which shifts every
%% domain equally and buys nothing but a recalibrated threshold:
%%
%%   age_days          SCORES. The strongest signal there is for throwaway ad
%%                     infrastructure, and graduated so "3 weeks old" and "3 years
%%                     old" are not the same claim.
%%   pending_delete    SCORES. Rare, and unambiguous: the registration is being
%%                     abandoned while the domain is still serving your clients.
%%   privacy_protected TAG ONLY. Registrant redaction is near-universal
%%                     post-GDPR — whole TLDs redact by policy — so it fires on
%%                     the legitimate and the malicious alike.
%%   has_transfer_lock TAG ONLY. clientTransferProhibited is absent for the first
%%                     60 days after registration by ICANN rule, so "no lock"
%%                     mostly restates "recently registered", which age already
%%                     scores. Double-counting one fact is not two signals.
%%
%% Every field is optional: a cached negative entry, a partial RDAP response or a
%% registry that omits a section all yield `undefined`, which MUST score 0 rather
%% than crash the scan. Only a POSITIVE signal scores.
score_rdap(RdapData) ->
    AgeScore = case maps:get(age_days, RdapData, undefined) of
        D when is_integer(D), D < 30 -> 3;
        D when is_integer(D), D < 180 -> 2;
        D when is_integer(D), D < 365 -> 1;
        _ -> 0
    end,
    DeleteScore = case maps:get(pending_delete, RdapData, undefined) of
        true -> 3;
        _ -> 0
    end,
    AgeScore + DeleteScore.

%% Tags are namespaced `rdap:` so provenance survives everywhere the reason list
%% travels — the Threats table, the per-client scan, and the raw
%% suspicious_candidates.reasons rows in Postgres. The UI colours any tag with
%% this prefix differently, which needs no shared catalogue of tag names: the
%% name carries its own source.
rdap_reasons(RdapData) ->
    R1 = case maps:get(age_days, RdapData, undefined) of
        D when is_integer(D), D < 180 -> [<<"rdap:new_domain">>];
        _ -> []
    end,
    R2 = case maps:get(has_transfer_lock, RdapData, undefined) of
        false -> [<<"rdap:no_transfer_lock">>];
        _ -> []
    end,
    R3 = case maps:get(pending_delete, RdapData, undefined) of
        true -> [<<"rdap:pending_delete">>];
        _ -> []
    end,
    R4 = case maps:get(privacy_protected, RdapData, undefined) of
        true -> [<<"rdap:privacy_protected">>];
        _ -> []
    end,
    R1 ++ R2 ++ R3 ++ R4.

%% ── Postgres helpers ─────────────────────────────────────────

db_call(query, Sql) ->
    bifrost_db_pool:query(Sql).
db_call(equery, Sql, Params) ->
    bifrost_db_pool:equery(Sql, Params).

respond_html(Code, Body, Req0) when is_binary(Body) ->
    Req = cowboy_req:reply(Code, #{<<"content-type">> => <<"text/html; charset=utf-8">>}, Body, Req0),
    {ok, Req, []}.

%% ── JSON response ────────────────────────────────────────────

respond(Code, Body, Req0) ->
    Bin = jsx:encode(Body),
    Req = cowboy_req:reply(Code, #{<<"content-type">> => <<"application/json">>}, Bin, Req0),
    {ok, Req, []}.

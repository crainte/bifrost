-module(bifrost_domain_analyzer).
-behaviour(gen_server).

%% Periodically scans recently-forwarded domains for algorithmically-generated
%% / throwaway ad domains (high entropy, numbered subdomains, young registration,
%% burst hits) and records high scorers as pending candidates for the Threats
%% page. Read-only w.r.t. DNS resolution — control-plane analysis only.
%%
%% Cluster-wide this is a SINGLETON: the scan reads the shared query_log and
%% upserts shared tables, so it has no shard key, and running it on every node
%% just multiplies RDAP lookups and header probes against third parties for the
%% same domains. Same shape as bifrost_ptr_warmer, so it uses the same election
%% (bifrost_cluster:is_leader/1). Shardable work uses a per-resource lock
%% instead — see bifrost_blocklist_manager:try_fetch/4.
%%
%% ONE SCAN AT A TIME, CLUSTER-WIDE. Scans issue RDAP requests to third-party
%% registries; two overlapping scans both miss rdap_cache for the same new
%% domains and both hit the registry. (bifrost_rdap's claim row now also stops
%% the duplicate request, and paces each registry, but overlapping scans would
%% still double header probes and upserts.) So the GenServer monitors the scan it
%% spawned and drops every trigger (timer tick or manual) while it runs, and a
%% manual scan_now/0 on a non-leader is forwarded to the leader instead of
%% running locally beside the leader's scan.

-export([start_link/0, scan_now/0, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
%% spawn_monitor/3 target; the domain_analyzer_scan env can replace it (tests).
-export([run_scan/0, find_candidates/0, rank_candidates/1]).

-define(SCAN_INTERVAL, 15 * 60 * 1000).  %% 15 minutes
-define(FIRST_SCAN_DELAY, 60 * 1000).    %% 1 min after boot (let traffic accrue)
-define(WINDOW_HOURS, 24).
-define(SCORE_THRESHOLD, 3).             %% require ~2+ signals
-define(RDAP_TOP, 15).                   %% enrich only the N highest scorers
-define(LEADER, bifrost_domain_analyzer_leader).  %% cluster-wide singleton name

-record(state, {scan :: undefined | {pid(), reference()},
                scans_started = 0 :: non_neg_integer()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Manual trigger. Never runs a scan next to one already in flight, on this or
%% any other node; see the module header.
scan_now() ->
    gen_server:cast(?MODULE, scan).

status() ->
    gen_server:call(?MODULE, status).

init([]) ->
    logger:info("~s started", [?MODULE]),
    erlang:send_after(?FIRST_SCAN_DELAY, self(), scan),
    {ok, #state{}}.

handle_call(status, _From, State = #state{scan = Scan, scans_started = N}) ->
    {reply, #{running => Scan =/= undefined, scans_started => N}, State};
handle_call(_Req, _From, State) ->
    {reply, ok, State}.

%% Manual request: run it here if we lead, otherwise hand it to the leader.
%% Forwarded requests are never forwarded again, so a leadership change in
%% flight drops one request rather than bouncing it between nodes.
handle_cast(scan, State) ->
    case bifrost_cluster:is_leader(?LEADER) of
        true -> {noreply, maybe_start_scan(State)};
        false ->
            case global:whereis_name(?LEADER) of
                Pid when is_pid(Pid) -> gen_server:cast(Pid, forwarded_scan);
                undefined -> ok
            end,
            {noreply, State}
    end;
handle_cast(forwarded_scan, State) ->
    case bifrost_cluster:is_leader(?LEADER) of
        true -> {noreply, maybe_start_scan(State)};
        false -> {noreply, State}
    end;
handle_cast(_Req, State) ->
    {noreply, State}.

handle_info(scan, State) ->
    %% Only the cluster leader scans on the timer; standbys skip. The election
    %% must run on THIS long-lived GenServer process, not the spawned worker:
    %% global frees the name when the registered process dies, and the worker
    %% exits after every scan.
    Next = case bifrost_cluster:is_leader(?LEADER) of
        true -> maybe_start_scan(State);
        false -> State
    end,
    erlang:send_after(?SCAN_INTERVAL, self(), scan),
    {noreply, Next};
handle_info({'DOWN', Ref, process, Pid, _}, State = #state{scan = {Pid, Ref}}) ->
    {noreply, State#state{scan = undefined}};
handle_info(_Info, State) ->
    {noreply, State}.

%% Runs off the GenServer process (RDAP blocks on network I/O), monitored so the
%% guard clears however the scan ends. run_scan/0 catches its own errors, but a
%% kill or a crash outside that try must not leave the guard stuck closed.
maybe_start_scan(State = #state{scan = {_, _}}) ->
    logger:info("domain_analyzer: scan already running, request skipped"),
    State;
maybe_start_scan(State = #state{scans_started = N}) ->
    {M, F, A} = application:get_env(bifrost, domain_analyzer_scan,
                                    {?MODULE, run_scan, []}),
    State#state{scan = spawn_monitor(M, F, A), scans_started = N + 1}.

%% ── Scan pipeline ────────────────────────────────────────────

run_scan() ->
    try
        Candidates = find_candidates(),
        logger:info("domain_analyzer: ~p candidates over threshold", [length(Candidates)]),
        %% Enrich the top N with RDAP age, then persist all.
        {Top, Rest} = lists:split(min(?RDAP_TOP, length(Candidates)), Candidates),
        Enriched = [enrich(C) || C <- Top] ++ Rest,
        lists:foreach(fun upsert_candidate/1, Enriched),
        %% Auto-block only the ENRICHED set (they have the RDAP age gate).
        maybe_auto_block(Enriched)
    catch
        Class:Reason:Stack ->
            logger:error("domain_analyzer scan failed: ~p:~p~n~p", [Class, Reason, Stack])
    end.

%% Auto-block gate: opt-in, and only when the domain is BOTH lexically/probe
%% suspicious (score >= min) AND recently registered (age < max). Requires a
%% known age — if RDAP gave no age, never auto-block (age is the confirmation).
maybe_auto_block(Candidates) ->
    case setting(<<"auto_block_enabled">>, <<"false">>) of
        <<"true">> ->
            MinScore = setting_int(<<"auto_block_min_score">>, 6),
            MaxAge   = setting_int(<<"auto_block_max_age_days">>, 30),
            lists:foreach(fun(C) -> auto_block_one(C, MinScore, MaxAge) end, Candidates);
        _ ->
            ok
    end.

auto_block_one(#{domain := Domain, score := Score} = C, MinScore, MaxAge) ->
    Age = maps:get(age_days, C, undefined),
    case (Score >= MinScore) andalso is_integer(Age) andalso (Age < MaxAge) of
        true ->
            logger:warning("auto-blocking ~s (score ~p, age ~p days)", [Domain, Score, Age]),
            _ = bifrost_db_pool:equery(
                "INSERT INTO manual_blocks (domain) VALUES ($1) ON CONFLICT DO NOTHING", [Domain]),
            _ = bifrost_db_pool:equery(
                "UPDATE suspicious_candidates SET status='blocked', updated_at=now() WHERE domain=$1",
                [Domain]),
            catch bifrost_api_handler:push_manual_blocks(),
            catch bifrost_mnesia:broadcast_evict(Domain),
            ok;
        false ->
            ok
    end.

setting(Key, Default) ->
    case bifrost_db_pool:equery("SELECT value FROM settings WHERE key = $1", [Key]) of
        {ok, _, [{V}]} -> V;
        _ -> Default
    end.

setting_int(Key, Default) ->
    try binary_to_integer(setting(Key, integer_to_binary(Default)))
    catch _:_ -> Default
    end.

%% Pull distinct forwarded domains in the window, score them, keep high scorers
%% that aren't already blocked or dismissed, or covered by an active campaign
%% suppression (bifrost_threat_campaigns).
find_candidates() ->
    Sql = "SELECT q.domain, COUNT(*) AS hits "
          "FROM query_log q "
          "WHERE q.queried_at > now() - ($1 || ' hours')::interval "
          "  AND q.action NOT IN ('BIFROST_BLOCK','BIFROST_CACHE') "
          "  AND q.domain NOT IN (SELECT domain FROM suspicious_candidates WHERE status IN ('blocked','dismissed')) "
          "  AND NOT " ++ bifrost_threat_campaigns:suppressed_sql("q.domain", "q.client_ip") ++ " "
          "GROUP BY q.domain ORDER BY hits DESC LIMIT 2000",
    case bifrost_db_pool:equery(Sql, [integer_to_list(?WINDOW_HOURS)]) of
        {ok, _, Rows} ->
            rank_candidates(Rows);
        _ ->
            []
    end.

rank_candidates(Rows) ->
    Scored = lists:filtermap(fun({Domain, Hits}) ->
        Score = bifrost_api_handler:score_domain(Domain, Hits),
        case bifrost_api_handler:threat_eligible_domain(Domain)
             andalso Score >= ?SCORE_THRESHOLD of
            true ->
                {true, #{domain => Domain, score => Score, hits => Hits,
                         reasons => bifrost_api_handler:score_reasons(Domain, Hits)}};
            false -> false
        end
    end, Rows),
    lists:sort(fun(A, B) -> maps:get(score, A) >= maps:get(score, B) end, Scored).

%% Enrich a candidate with out-of-band signals: RDAP registry data and a header
%% probe (CORS/CSP). Both cached — a client already fetched this domain, so a HEAD
%% from us leaks nothing new.
%%
%% RDAP contributes BOTH score and tags. Previously every field except the age was
%% fetched and thrown away, so the Threats page could not rank on registry data
%% and could not show why the registry made a domain look bad. Which fields earn
%% score, and which are tags only, is argued in bifrost_api_handler:score_rdap/1.
%%
%% Note the interaction with auto-block: the age term is a constant +3 across the
%% ENTIRE population the gate admits (age < max_age), so folding it into the score
%% would have loosened that gate by exactly 3 for every candidate. Migration 011
%% shifts auto_block_min_score by the same 3 to hold the gate where it was — see
%% the migration for the arithmetic.
%%
%% `sync`: this runs on the scan worker, never a request process, so a due
%% lookup is fetched inline — claimed and paced by bifrost_rdap, so the top
%% ?RDAP_TOP domains go out at most one per second per registry.
enrich(#{domain := Domain} = C) ->
    Rdap = bifrost_api_handler:rdap_cached(Domain, sync),
    {ProbeScore, ProbeReasons} = header_probe(Domain),
    C#{
        age_days => maps:get(age_days, Rdap, undefined),
        rdap_lookup => maps:get(lookup, Rdap, unavailable),
        score => maps:get(score, C)
                 + ProbeScore
                 + bifrost_api_handler:score_rdap(Rdap),
        reasons => lists:usort(maps:get(reasons, C)
                               ++ ProbeReasons
                               ++ bifrost_api_handler:rdap_reasons(Rdap))
    }.

%% Out-of-band header probe: HEAD the candidate over HTTPS, score absurdly
%% permissive CORS (Access-Control-Allow-Origin: *) and missing CSP. Cached so
%% repeated scans don't re-probe. Signal only — never gates auto-block.
header_probe(Domain) ->
    case cached_probe(Domain) of
        {ok, Cors, Csp} -> probe_score(Cors, Csp);
        miss ->
            {Cors, Csp} = do_probe(Domain),
            cache_probe(Domain, Cors, Csp),
            probe_score(Cors, Csp)
    end.

do_probe(Domain) ->
    Url = "https://" ++ binary_to_list(Domain) ++ "/",
    %% HEAD, no redirect chase, tight timeout, headers only.
    case httpc:request(head, {Url, []},
                       [{timeout, 3000}, {connect_timeout, 2000}, {autoredirect, false}],
                       []) of
        {ok, {{_, _Code, _}, Headers, _}} ->
            LHeaders = [{string:lowercase(K), V} || {K, V} <- Headers],
            Cors = case proplists:get_value("access-control-allow-origin", LHeaders) of
                "*" -> true;
                _ -> false
            end,
            Csp = proplists:is_defined("content-security-policy", LHeaders),
            {Cors, Csp};
        _ ->
            %% Unreachable/timeout/TLS failure — no signal (not evidence of guilt).
            {false, true}
    end.

%% Permissive CORS is a weak tell; missing CSP on top nudges further. Small
%% weights — this only supplements the lexical + RDAP signals.
probe_score(true, false) -> {2, [<<"permissive_cors">>, <<"no_csp">>]};
probe_score(true, true)  -> {1, [<<"permissive_cors">>]};
probe_score(false, false) -> {1, [<<"no_csp">>]};
probe_score(false, true) -> {0, []}.

cached_probe(Domain) ->
    case bifrost_db_pool:equery(
        "SELECT cors_wildcard, has_csp FROM probe_cache WHERE domain = $1", [Domain]) of
        {ok, _, [{Cors, Csp}]} -> {ok, Cors, Csp};
        _ -> miss
    end.

cache_probe(Domain, Cors, Csp) ->
    bifrost_db_pool:equery(
        "INSERT INTO probe_cache (domain, cors_wildcard, has_csp) VALUES ($1, $2, $3) "
        "ON CONFLICT (domain) DO NOTHING",
        [Domain, Cors, Csp]).

%% Upsert as pending. Never resurrects a blocked/dismissed row (the WHERE in
%% find_candidates already excludes them, and ON CONFLICT only bumps a pending).
upsert_candidate(#{domain := Domain, score := Score, hits := Hits, reasons := Reasons} = C) ->
    Age = maps:get(age_days, C, undefined),
    Lookup = atom_to_binary(maps:get(rdap_lookup, C, unavailable)),
    ReasonsJson = jsx:encode(Reasons),
    bifrost_db_pool:equery(
        "INSERT INTO suspicious_candidates "
        "  (domain, score, reasons, hits, age_days, rdap_lookup, updated_at) "
        "VALUES ($1, $2, $3::jsonb, $4, $5, $6, now()) "
        "ON CONFLICT (domain) DO UPDATE SET "
        "  score = $2, reasons = $3::jsonb, hits = $4, "
        "  age_days = COALESCE($5, suspicious_candidates.age_days), "
        "  rdap_lookup = CASE WHEN $6 = 'unavailable' "
        "    AND suspicious_candidates.rdap_lookup = 'done' THEN 'done' ELSE $6 END, "
        "  updated_at = now() "
        "WHERE suspicious_candidates.status = 'pending'",
        [Domain, Score, ReasonsJson, Hits, Age, Lookup]),
    ok.

-module(bifrost_blocklist_manager).
-behaviour(gen_server).

-export([start_link/0, on_client_connected/0, refresh_lists/0, force_refresh/0, parse_line/1,
         parse_blocklist/1, is_hydrated/0, enabled_list_ids/0]).
%% Exported for the cluster test suite, which drives the real fetch path across
%% real nodes and must build the same lock id the production path uses.
-export([fetch_lock_id/1, fetch_lock_nodes/0, try_fetch/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(TIMEOUT, 30000).
-define(BATCH_SIZE, 10000).
-define(REFRESH_INTERVAL, 24 * 60 * 60 * 1000).  %% 24 hours
-define(FRESHNESS_SECONDS, 24 * 60 * 60).         %% 24 hours in seconds
%% >0 matters: with 0 retries simultaneous requesters can ALL be denied. See
%% try_fetch/4.
-define(FETCH_LOCK_RETRIES, 3).
%% Re-attempt a failed hydration. Short: the pod serves no DNS until it succeeds.
-define(HYDRATION_RETRY, 10000).

-record(state, {
    hydrated :: boolean()
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

on_client_connected() ->
    gen_server:cast(?MODULE, client_connected).

refresh_lists() ->
    gen_server:cast(?MODULE, refresh_lists).

force_refresh() ->
    gen_server:cast(?MODULE, force_refresh).

init([]) ->
    logger:info("~s started", [?MODULE]),
    _ = inets:start(),
    _ = ssl:start(),
    set_hydrated(false),
    mnesia:subscribe({table, blocklist_cache, simple}),
    mnesia:subscribe({table, cache_propagation, simple}),
    mnesia:subscribe({table, cache_propagation_v2, simple}),
    mnesia:subscribe({table, cache_evict, simple}),
    mnesia:subscribe({table, config_reload, simple}),
    {ok, #state{hydrated = false}}.

%% Whether the LOCAL Rust process currently holds hydrated state. Read by the
%% readiness probe, so it must not be a call into this GenServer — during
%% hydration this process is busy pushing millions of domains and a call would
%% time out. persistent_term is written twice per Rust lifetime, read cheaply.
is_hydrated() ->
    persistent_term:get({?MODULE, hydrated}, false).

set_hydrated(Bool) ->
    persistent_term:put({?MODULE, hydrated}, Bool).

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%% A reconnect means a BRAND NEW Rust process with empty state, so this must run
%% on EVERY connect, not just the first. Guarding it on `hydrated = false` meant
%% that after a Rust crash the restarted process never received reload_complete,
%% left its ready flag false, and SERVFAILed every query for the life of the pod
%% — while liveness and readiness both stayed green so k8s kept sending it
%% traffic. State#state.hydrated now only tracks whether the periodic refresh
%% timer is already armed, so reconnects cannot stack timers.
handle_cast(client_connected, State = #state{hydrated = TimerArmed}) ->
    logger:info("Rust client connected — starting state hydration"),
    %% Drops this pod out of the k8s Service until Rust can filter again.
    set_hydrated(false),
    try
        Config = get_config(),
        ok = bifrost_dns_settings_server:apply_current(),
        send_acl(Config),
        load_blocklists(),
        %% Push operational config that lives in Postgres (survives restart).
        catch bifrost_api_handler:push_rewrites(),
        catch bifrost_api_handler:push_allowlist(),
        catch bifrost_api_handler:push_manual_blocks(),
        catch bifrost_api_handler:push_client_blocks(),
        %% A restarted Rust starts with filtering ON; re-apply the cluster pause.
        catch bifrost_socket_server:send_message(bifrost_config_server:protection_message()),
        bifrost_socket_server:send_message(#{type => <<"reload_complete">>}),
        set_hydrated(true),
        logger:info("state hydration complete, reload_complete sent"),
        case TimerArmed of
            false -> erlang:send_after(?REFRESH_INTERVAL, self(), refresh_blocklists);
            true -> ok
        end,
        %% Hydration pulled every list (millions of binaries) through this heap;
        %% hibernate so it is compacted now rather than retained as garbage
        %% (measured: ~170MB held until the next GC).
        {noreply, State#state{hydrated = true}, hibernate}
    catch
        Class:Reason:Stack ->
            %% Rust never got reload_complete, so it is still SERVFAILing every
            %% query. Leave the readiness flag false so k8s keeps this pod out of
            %% rotation, and RETRY — nothing else will. Without a retry a single
            %% transient failure (e.g. reading blocklist_cache while the node is
            %% still merging the cluster schema at boot) left the pod dead for
            %% DNS until someone restarted it by hand.
            logger:error("hydration failed, retrying in ~pms: ~p:~p~n~p",
                         [?HYDRATION_RETRY, Class, Reason, Stack]),
            erlang:send_after(?HYDRATION_RETRY, self(), retry_hydration),
            {noreply, State#state{hydrated = TimerArmed}, hibernate}
    end;
handle_cast(refresh_lists, State = #state{hydrated = true}) ->
    logger:info("manual blocklist refresh triggered"),
    spawn(fun() ->
        try
            refresh_blocklists()
        catch C:R:S ->
            logger:error("manual refresh failed: ~p:~p~n~p", [C, R, S])
        end
    end),
    {noreply, State};
handle_cast(force_refresh, State = #state{hydrated = true}) ->
    logger:info("force refresh triggered — re-fetching + re-parsing all lists (ignore ETag/freshness)"),
    spawn(fun() ->
        try
            force_refresh_all()
        catch C:R:S ->
            logger:error("force refresh failed: ~p:~p~n~p", [C, R, S])
        end
    end),
    {noreply, State};
handle_cast(refresh_lists, State) ->
    %% Not yet hydrated, ignore
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.

%% Scheduled by a failed hydration. Re-runs the exact same path; if a Rust
%% reconnect already hydrated us in the meantime there is nothing to do.
handle_info(retry_hydration, State) ->
    case is_hydrated() of
        true ->
            {noreply, State};
        false ->
            logger:info("retrying state hydration"),
            handle_cast(client_connected, State)
    end;
handle_info(refresh_blocklists, State) ->
    logger:info("starting periodic blocklist refresh"),
    try
        refresh_blocklists(),
        erlang:send_after(?REFRESH_INTERVAL, self(), refresh_blocklists),
        {noreply, State, hibernate}
    catch
        Class:Reason:Stack ->
            logger:error("blocklist refresh failed: ~p:~p~n~p", [Class, Reason, Stack]),
            erlang:send_after(?REFRESH_INTERVAL, self(), refresh_blocklists),
            {noreply, State, hibernate}
    end;
%% Mnesia table change event: another node updated a list, re-send to local Rust
handle_info({mnesia_table_event, {write, {blocklist_cache, ListId, Domains, _, _}, _ActivityId}}, State) ->
    logger:info("blocklist ~s updated in Mnesia, re-sending to Rust", [ListId]),
    send_to_rust(ListId, Domains),
    %% The event carried the whole list into this heap; compact it now.
    {noreply, State, hibernate};
%% Cache propagation event: another node cached a domain, push to local Rust
handle_info({mnesia_table_event, {write, {cache_propagation, Domain, Qtype, Response, TTL}, _ActivityId}}, State) ->
    logger:info("cache entry for ~s (qtype ~p) propagated, sending to Rust", [Domain, Qtype]),
    ResponseB64 = base64:encode(Response),
    bifrost_socket_server:send_message(#{
        type => <<"store_cache">>,
        domain => Domain,
        qtype => Qtype,
        response => ResponseB64,
        ttl => TTL
    }),
    {noreply, State};
handle_info({mnesia_table_event, {write, {cache_propagation_v2, {Domain, Qtype, Fingerprint, Variant},
                                          Response, TTL, Expires}, _ActivityId}}, State) ->
    bifrost_socket_server:send_message(#{
        type => <<"store_cache">>, domain => Domain, qtype => Qtype,
        response => base64:encode(Response), ttl => TTL, fingerprint => Fingerprint,
        variant => Variant, expires_at_ms => Expires}),
    {noreply, State};
%% Cache eviction event: a node busted a domain, push evict to local Rust
handle_info({mnesia_table_event, {write, {cache_evict, Domain, _Nonce}, _ActivityId}}, State) ->
    logger:info("cache evict for ~s propagated, sending to Rust", [Domain]),
    bifrost_socket_server:send_message(#{
        type => <<"evict_cache">>,
        domain => Domain
    }),
    {noreply, State};
%% Blocklist reload event: enable/disable/add/delete of a URL blocklist on
%% another node. Re-sync this node's Rust from the (already replicated) Mnesia
%% cache + config: clear lists no longer enabled, (re)load the enabled ones.
handle_info({mnesia_table_event, {write, {config_reload, blocklists, _Nonce}, _ActivityId}}, State) ->
    logger:info("blocklist reload propagated, re-syncing local Rust"),
    _ = catch sync_blocklists_to_rust(),
    {noreply, State};
%% Operational-config reload event: another node changed manual blocks /
%% allowlist / rewrites / client blocks in Postgres. Re-push all of it to THIS
%% node's Rust so every pod stays consistent behind a load balancer.
handle_info({mnesia_table_event, {write, {config_reload, _What, _Nonce}, _ActivityId}}, State) ->
    logger:info("operational config reload propagated, re-pushing to local Rust"),
    _ = catch bifrost_api_handler:push_manual_blocks(),
    _ = catch bifrost_api_handler:push_allowlist(),
    _ = catch bifrost_api_handler:push_rewrites(),
    _ = catch bifrost_api_handler:push_client_blocks(),
    {noreply, State};
%% A blocklist was deleted from Mnesia on another node — clear it from local Rust.
handle_info({mnesia_table_event, {delete, {blocklist_cache, ListId}, _ActivityId}}, State) ->
    logger:info("blocklist ~s deleted in Mnesia, clearing from Rust", [ListId]),
    bifrost_socket_server:send_message(#{type => <<"clear_blocklist">>, list_id => list_id_bin(ListId)}),
    {noreply, State};
handle_info({mnesia_table_event, _Event}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% ── Internal ────────────────────────────────────────────────

get_config() ->
    case bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end.

%% ConfigMap `network.allowed_clients` (CIDRs). Absent = everyone may query.
send_acl(Config) ->
    Network = case maps:find(network, Config) of
        {ok, N} when is_list(N) -> N;
        _ -> []
    end,
    Allowed = [list_to_binary(C) || C <- proplists:get_value(allowed_clients, Network, [])],
    bifrost_socket_server:send_message(#{type => <<"set_acl">>, allowed_clients => Allowed}).

%% ── Load / Refresh ──────────────────────────────────────────

%% Initial load (on Rust client connect): try Mnesia cache, fall back to HTTP.
load_blocklists() ->
    Config = get_config(),
    each_list(fun load_one_list/1, get_blocklist_entries(Config)).

load_one_list(Entry) ->
    case proplists:get_value(enabled, Entry, true) of
        true ->
            Name = proplists:get_value(name, Entry, "unknown"),
            Url  = proplists:get_value(url, Entry, ""),
            case bifrost_mnesia:read_cache(Name) of
                {ok, Domains, _ETag, _FetchedAt} ->
                    logger:info("blocklist ~s: ~p domains loaded from Mnesia cache",
                                [Name, length(Domains)]),
                    send_to_rust(Name, Domains);
                not_found ->
                    case fetch_and_cache(Name, Url) of
                        {ok, Domains} ->
                            send_to_rust(Name, Domains);
                        _ ->
                            ok
                    end
            end;
        false ->
            ok
    end.

%% Periodic refresh: delegation to per-list coordinator
%% One list at a time, collecting garbage between them: a refresh walks every
%% list in one process, and without this the parse garbage of all of them piled
%% up into a single peak (measured >1GB during a forced refresh).
refresh_blocklists() ->
    Config = get_config(),
    each_list(fun refresh_one_list/1, get_blocklist_entries(Config)).

each_list(Fun, Entries) ->
    lists:foreach(fun(E) -> Fun(E), erlang:garbage_collect() end, Entries).

refresh_one_list(Entry) ->
    case proplists:get_value(enabled, Entry, true) of
        true ->
            Name = proplists:get_value(name, Entry, "unknown"),
            Url  = proplists:get_value(url, Entry, ""),
            case bifrost_mnesia:read_cache(Name) of
                {ok, Domains, ETag, FetchedAt} ->
                    case bifrost_mnesia:is_fresh(FetchedAt, ?FRESHNESS_SECONDS) of
                        true ->
                            logger:info("blocklist ~s: cache fresh (~p domains), re-sending",
                                        [Name, length(Domains)]),
                            send_to_rust(Name, Domains);
                        false ->
                            try_fetch(Name, Url, ETag)
                    end;
                not_found ->
                    try_fetch(Name, Url, undefined)
            end;
        false ->
            ok
    end.

%% Force refresh: re-fetch + re-parse every enabled list, ignoring both the
%% freshness window AND the stored ETag (undefined => no If-None-Match => the
%% server returns 200 with a body => re-parse under current parser code).
%% This is the operator lever after a parser fix or a bad blocklist state.
force_refresh_all() ->
    Config = get_config(),
    each_list(fun force_refresh_one_list/1, get_blocklist_entries(Config)),
    %% A parser change can flip block status for many domains; flush the whole
    %% DNS cache so any cached answer re-resolves under the new blocklist state.
    bifrost_socket_server:send_message(#{type => <<"clear_cache">>}),
    logger:info("force refresh complete, DNS cache flushed").
force_refresh_one_list(Entry) ->
    case proplists:get_value(enabled, Entry, true) of
        true ->
            Name = proplists:get_value(name, Entry, "unknown"),
            Url  = proplists:get_value(url, Entry, ""),
            try_fetch(Name, Url, undefined, force);
        false ->
            ok
    end.

%% global:set_lock/3 takes Id = {ResourceId, LockRequesterId}. Two things must
%% be right or cluster-wide exclusion silently degrades to "every pod fetches":
%%   - LockRequesterId must be UNIQUE per requester. Identical requester ids
%%     SHARE a lock by design, so a constant id grants every node the lock.
%%   - Nodes must be [node()|nodes()]; [node()] locks locally and always wins.
%% Both are covered by bifrost_cluster_SUITE against real nodes.
fetch_lock_id(Name) -> {{bifrost_fetch, Name}, self()}.

fetch_lock_nodes() -> [node() | nodes()].

try_fetch(Name, Url, ETag) ->
    try_fetch(Name, Url, ETag, refresh).

%% Mode is `refresh` (honour the freshness window) or `force` (operator lever —
%% always re-fetch). See force_refresh_all/0.
try_fetch(Name, Url, ETag, Mode) ->
    LockId = fetch_lock_id(Name),
    Nodes = fetch_lock_nodes(),
    %% Retries is load-bearing. With 0, two pods asking at the same instant can
    %% BOTH be denied: each is granted by a different node, neither gets the
    %% full set, both back off. Every pod's refresh timer starts at boot, so
    %% they are aligned and a whole cycle can pass with nobody fetching.
    %% Retrying breaks the symmetry via global's randomised backoff.
    case global:set_lock(LockId, Nodes, ?FETCH_LOCK_RETRIES) of
        true ->
            try
                %% Double-checked: we may have been queued behind the node that
                %% just fetched this very list, so re-read freshness rather than
                %% spend a redundant HTTP request.
                case Mode =:= force orelse is_stale(Name) of
                    true ->
                        case fetch_and_cache(Name, Url, ETag) of
                            {ok, _Domains} ->
                                %% Deliberately does not push to Rust here: the
                                %% Mnesia write fires a blocklist_cache table
                                %% event on every replica, including this node,
                                %% and that handler does the push. One code path
                                %% for winner and peers.
                                logger:info("blocklist ~s: fetched and cached in Mnesia", [Name]);
                            _ ->
                                ok
                        end;
                    false ->
                        logger:info("blocklist ~s: refreshed by another node while we waited",
                                    [Name])
                end
            after
                global:del_lock(LockId, Nodes)
            end;
        false ->
            logger:info("blocklist ~s: refresh locked by another node, waiting for Mnesia update",
                        [Name])
    end.

is_stale(Name) ->
    case bifrost_mnesia:read_cache(Name) of
        {ok, _Domains, _ETag, FetchedAt} ->
            not bifrost_mnesia:is_fresh(FetchedAt, ?FRESHNESS_SECONDS);
        not_found ->
            true
    end.

%% Names (Mnesia blocklist_cache keys) of the lists Rust is filtering with, so
%% control-plane analysis (bifrost_threat_context) matches against exactly the
%% enabled set and never against a cached-but-disabled list.
enabled_list_ids() ->
    [proplists:get_value(name, E, "unknown")
     || E <- get_blocklist_entries(get_config()), proplists:get_value(enabled, E, true)].

get_blocklist_entries(Config) ->
    %% Get lists from config file
    FileLists = case maps:find(blocklists, Config) of
        {ok, {default, L}} when is_list(L) -> L;
        {ok, L} when is_list(L) -> L;
        _ -> []
    end,
    %% Get lists from Postgres (UI-added)
    DbLists = get_db_blocklists(),
    %% Merge: DB entries override file entries with same name
    FileNames = [proplists:get_value(name, E, "") || E <- FileLists],
    FilteredDb = [E || E <- DbLists, not lists:member(proplists:get_value(name, E, ""), FileNames)],
    FileLists ++ FilteredDb.

%% UI-added lists live in Postgres; the snapshot keeps them loadable (from the
%% Mnesia blocklist cache) when it is down. They are 11 of the 13 lists on the
%% dev cluster, so losing them would mean near-unfiltered DNS during an outage.
get_db_blocklists() ->
    Sql = "SELECT name, url, enabled::text FROM blocklists WHERE source = 'ui' ORDER BY name",
    ToEntries = fun(Rows) ->
        [[{name, binary_to_list(N)}, {url, binary_to_list(U)}, {enabled, E =:= <<"true">>}]
         || {N, U, E} <- Rows]
    end,
    case bifrost_opconfig:read(ui_blocklists, {Sql, ToEntries}) of
        {ok, Entries} -> Entries;
        error -> []
    end.

%% ── HTTP fetch with Mnesia cache ────────────────────────────

fetch_and_cache(Name, Url) ->
    fetch_and_cache(Name, Url, undefined).

fetch_and_cache(Name, Url, ETag) ->
    logger:info("fetching blocklist ~s from ~s", [Name, Url]),
    case fetch_url_with_etag(Url, ETag, ?TIMEOUT) of
        {ok, Body, NewETag} ->
            Domains = parse_blocklist(Body),
            logger:info("blocklist ~s: ~p domains parsed", [Name, length(Domains)]),
            bifrost_mnesia:write_cache(Name, Domains, NewETag),
            {ok, Domains};
        unchanged ->
            %% 304 = our cached copy is confirmed current. Rewrite it with a
            %% fresh timestamp for two reasons: the freshness window advances
            %% (next cycle skips the HTTP entirely), and the resulting Mnesia
            %% table event re-pushes the list to EVERY node's Rust — peers that
            %% skipped this fetch on the cluster lock are fed from here. Without
            %% the touch, a locked-out peer receives nothing on a 304.
            bifrost_mnesia:touch_cache(Name),
            logger:info("blocklist ~s: unchanged (304), cache freshened", [Name]),
            unchanged;
        {error, Reason} ->
            logger:warning("failed to fetch blocklist ~s: ~p", [Name, Reason]),
            {error, Reason}
    end.

%% ── IPC helpers ─────────────────────────────────────────────

%% Replace a list in Rust atomically: Rust stages the batches off to the side
%% and swaps them in on commit, so the old copy keeps blocking throughout. (A
%% clear followed by batched loads left a multi-second window, on every node,
%% every refresh, in which that list's domains resolved.)
%%
%% The list id MUST be a binary: Mnesia keys are Erlang strings, which jsx would
%% encode as a JSON array of ints; Rust then falls back to "unknown" and the real
%% list is never replaced.
send_to_rust(Name, Domains) ->
    Id = list_id_bin(Name),
    bifrost_socket_server:send_message(#{type => <<"begin_blocklist">>, list_id => Id}),
    send_blocklist_batches(Id, Domains),
    bifrost_socket_server:send_message(#{type => <<"commit_blocklist">>, list_id => Id}).

send_blocklist_batches(_Id, []) ->
    ok;
send_blocklist_batches(Id, Domains) ->
    {Batch, Rest} = take(?BATCH_SIZE, Domains, []),
    bifrost_socket_server:send_message(#{type => <<"load_blocklist">>, list_id => Id,
                                         entries => Batch}),
    send_blocklist_batches(Id, Rest).

%% O(N) split. length/1 on every batch made a 2.4M-entry list cost ~240 full
%% traversals per push.
take(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
take(_, [], Acc) -> {lists:reverse(Acc), []};
take(N, [H | T], Acc) -> take(N - 1, T, [H | Acc]).

%% Normalize a Mnesia list id (stored as a string) to a binary for JSON.
list_id_bin(Id) when is_binary(Id) -> Id;
list_id_bin(Id) when is_list(Id) -> list_to_binary(Id).

%% Re-sync this node's Rust blocklists from the (replicated) Mnesia cache +
%% current config: clear any list Rust may hold that is no longer enabled, then
%% (re)load every enabled list. Used by peers on a blocklists reload broadcast.
sync_blocklists_to_rust() ->
    Config = get_config(),
    Entries = get_blocklist_entries(Config),
    %% Clear disabled lists from Rust so a disable propagates cluster-wide.
    lists:foreach(fun(E) ->
        case proplists:get_value(enabled, E, true) of
            false ->
                Name = proplists:get_value(name, E, "unknown"),
                bifrost_socket_server:send_message(#{
                    type => <<"clear_blocklist">>, list_id => list_id_bin(Name)});
            true -> ok
        end
    end, Entries),
    %% Load enabled lists from the Mnesia cache (no HTTP; already replicated).
    lists:foreach(fun load_one_list/1, Entries).

%% ── HTTP fetch with ETag ────────────────────────────────────

fetch_url_with_etag(_Url, undefined, Timeout) ->
    case httpc:request(get, {_Url, []}, [{timeout, Timeout}],
                       [{body_format, binary}, {full_result, true}]) of
        {ok, {{_, 200, _}, Headers, Body}} ->
            {ok, Body, extract_etag(Headers)};
        {ok, {{_, Status, _}, _, _}} ->
            {error, {http_status, Status}};
        {error, Reason} ->
            {error, Reason}
    end;
fetch_url_with_etag(Url, ETag, Timeout) when is_binary(ETag) ->
    case httpc:request(get, {Url, [{"If-None-Match", binary_to_list(ETag)}]}, [{timeout, Timeout}],
                       [{body_format, binary}, {full_result, true}]) of
        {ok, {{_, 304, _}, _, _}} ->
            unchanged;
        {ok, {{_, 200, _}, Headers, Body}} ->
            {ok, Body, case extract_etag(Headers) of undefined -> ETag; V -> V end};
        {ok, {{_, Status, _}, _, _}} ->
            {error, {http_status, Status}};
        {error, Reason} ->
            {error, Reason}
    end.

extract_etag(Headers) ->
    case lists:keyfind("etag", 1, Headers) of
        {_, Value} -> list_to_binary(Value);
        false ->
            case lists:keyfind("ETag", 1, Headers) of
                {_, Value} -> list_to_binary(Value);
                false -> undefined
            end
    end.

%% ── Blocklist parsing ───────────────────────────────────────
%%
%% DNS can only block whole names. Following AdGuard's DNS filtering syntax, a
%% rule with any modifier the DNS layer cannot honour ($third-party, $script,
%% $domain=...) is IGNORED, never widened into a whole-domain block — otherwise
%% browser lists such as EasyList over-block. Only $important (no effect here:
%% there is one block action) and $badfilter (disables the named rule) apply.
%% https://adguard-dns.io/kb/general/dns-filtering-syntax/
%%
%% Exceptions (@@||name^) are kept as `@@name` entries. Rust scopes them to the
%% list that declared them, so a browser list's exception cannot unblock a name
%% that a security list blocks.

%% Walks the body line by line instead of splitting it into one list up front:
%% for a 2.4M-line list that intermediate list alone was ~150MB, and the whole
%% parse peaked at ~400MB over baseline (and took ~14s, mostly converting every
%% line to a charlist and back just to trim it).
parse_blocklist(Body) when is_binary(Body) ->
    {Blocks, Excepts, Bad} = parse_lines(Body, {[], [], []}),
    Disabled = sets:from_list(Bad, [{version, 2}]),
    Kept = case sets:size(Disabled) of
        0 -> Blocks;
        _ -> [D || D <- Blocks, not sets:is_element(D, Disabled)]
    end,
    lists:usort([<<"@@", D/binary>> || D <- Excepts] ++ Kept).

parse_lines(<<>>, Acc) ->
    Acc;
parse_lines(Body, {B, E, D} = Acc) ->
    {Line, Rest} = case binary:match(Body, <<"\n">>) of
        {Pos, 1} -> {binary:part(Body, 0, Pos),
                     binary:part(Body, Pos + 1, byte_size(Body) - Pos - 1)};
        nomatch -> {Body, <<>>}
    end,
    NewAcc = case classify(Line) of
        {block, Dom} -> {[Dom | B], E, D};
        {hosts_multi, Doms} -> {Doms ++ B, E, D};
        {except, Dom} -> {B, [Dom | E], D};
        {badfilter, Dom} -> {B, E, [Dom | D]};
        skip -> Acc
    end,
    parse_lines(Rest, NewAcc).

%% Classify one line: {block, D} | {except, D} | {badfilter, D} | skip. A hosts
%% line naming several hosts reports its first; parse_blocklist keeps them all.
parse_line(Line) ->
    case classify(Line) of
        {hosts_multi, [D | _]} -> {block, D};
        Other -> Other
    end.

classify(Line) ->
    case trim_binary(Line) of
        <<>> -> skip;
        <<"#", _/binary>> -> skip;
        <<"!", _/binary>> -> skip;
        <<"[", _/binary>> -> skip;
        <<"/", _/binary>> -> skip;
        <<"@@", Rule/binary>> ->
            case adblock_rule(Rule) of
                {ok, D, []} -> {except, D};
                _ -> skip
            end;
        <<"||", _/binary>> = Rule ->
            case adblock_rule(Rule) of
                {ok, D, []} -> {block, D};
                {ok, D, [badfilter]} -> {badfilter, D};
                _ -> skip
            end;
        Trimmed ->
            case is_cosmetic(Trimmed) of
                true -> skip;
                false -> hosts_or_plain(Trimmed)
            end
    end.

%% `||name^$mods` / `||name$mods`. Returns {ok, Name, Effects} where Effects is
%% what the DNS layer must do with the modifiers, or `unsupported`.
adblock_rule(<<"||", Rest/binary>>) ->
    {Pattern, Mods} = case binary:split(Rest, <<"$">>) of
        [P, M] -> {P, M};
        [P] -> {P, <<>>}
    end,
    Name = case Pattern of
        _ when byte_size(Pattern) > 0 ->
            case binary:last(Pattern) of
                $^ -> binary:part(Pattern, 0, byte_size(Pattern) - 1);
                _ -> Pattern
            end;
        _ -> Pattern
    end,
    case {domain_token(Name), modifiers(Mods)} of
        {{ok, D}, {ok, Effects}} -> {ok, D, Effects};
        _ -> unsupported
    end;
adblock_rule(_) ->
    unsupported.

modifiers(<<>>) -> {ok, []};
modifiers(Mods) ->
    lists:foldl(fun
        (_, unsupported) -> unsupported;
        (<<"important">>, Acc) -> Acc;
        (<<"badfilter">>, {ok, E}) -> {ok, [badfilter | E]};
        (_, _) -> unsupported
    end, {ok, []}, [trim_binary(M) || M <- binary:split(Mods, <<",">>, [global])]).

%% `example.com##.ad`, `example.com#@#.ad`, `example.com#$#...` — page rules.
is_cosmetic(Line) ->
    binary:match(Line, [<<"##">>, <<"#@#">>, <<"#$#">>, <<"#?#">>, <<"#%#">>]) =/= nomatch.

%% Hosts line (`IP name [name ...] [# comment]`) or a bare domain line.
hosts_or_plain(Line) ->
    Uncommented = hd(binary:split(Line, <<"#">>)),
    case [F || F <- binary:split(Uncommented, [<<" ">>, <<"\t">>], [global]), F =/= <<>>] of
        [] ->
            skip;
        [First | Names] ->
            case inet:parse_address(binary_to_list(First)) of
                {ok, _} -> hosts_names(Names);
                {error, _} when Names =:= [] ->
                    case domain_token(First) of
                        {ok, D} -> {block, D};
                        error -> skip
                    end;
                {error, _} -> skip
            end
    end.

%% A hosts line may list several names; the list API is one result per line,
%% so multi-name lines are expanded by parse_blocklist via this marker.
hosts_names(Names) ->
    case [D || N <- Names, {ok, D} <- [domain_token(N)]] of
        [] -> skip;
        [D] -> {block, D};
        Ds -> {hosts_multi, Ds}
    end.

%% A blockable name: has a dot, only hostname characters, not an IP literal.
%% A single leading `*.` is accepted and dropped (matching is subtree-wide).
%% Usually a sub-binary of the download; that does NOT pin the download, because
%% the Mnesia (ETS) write copies the data (measured: 0MB retained afterwards).
domain_token(Raw) ->
    Name0 = strip_trailing_dots(Raw),
    Name1 = case Name0 of
        <<"*.", Rest/binary>> -> Rest;
        _ -> Name0
    end,
    case byte_size(Name1) > 0 andalso hostname_chars(Name1, false, true) of
        {true, true} -> error;           % all digits and dots: an IPv4 literal
        {true, false} ->
            Name = lower(Name1),
            case is_local_hostname(Name) of
                true -> error;
                false -> {ok, Name}
            end;
        _ -> error
    end.

%% Returns {HasDot, AllNumeric} if every byte is a hostname character
%% (letters, digits, - . _), else false.
hostname_chars(<<>>, Dot, Numeric) -> {Dot, Numeric};
hostname_chars(<<$., T/binary>>, _, N) -> hostname_chars(T, true, N);
hostname_chars(<<C, T/binary>>, D, N) when C >= $0, C =< $9 -> hostname_chars(T, D, N);
hostname_chars(<<C, T/binary>>, D, _) when C >= $a, C =< $z; C >= $A, C =< $Z;
                                           C =:= $-; C =:= $_ -> hostname_chars(T, D, false);
hostname_chars(_, _, _) -> false.

%% ASCII lowercase. Returns the input untouched when it has no uppercase (the
%% common case): rebuilding every name roughly doubled parse memory, since each
%% copy is a heap binary the GC moves around.
lower(Bin) ->
    case has_upper(Bin) of
        true -> << <<(lower_byte(C))>> || <<C>> <= Bin >>;
        false -> Bin
    end.

has_upper(<<C, _/binary>>) when C >= $A, C =< $Z -> true;
has_upper(<<_, T/binary>>) -> has_upper(T);
has_upper(<<>>) -> false.

lower_byte(C) when C >= $A, C =< $Z -> C + 32;
lower_byte(C) -> C.

strip_trailing_dots(Bin) ->
    case byte_size(Bin) of
        0 -> Bin;
        N -> case binary:at(Bin, N - 1) of
                 $. -> strip_trailing_dots(binary:part(Bin, 0, N - 1));
                 _ -> Bin
             end
    end.

%% Boilerplate that hosts-format lists ship at the top. Blocking these would
%% break loopback resolution, not an ad.
is_local_hostname(Name) ->
    lists:member(Name, [<<"localhost.localdomain">>, <<"local.localdomain">>,
                        <<"localhost.local">>, <<"ip6-localhost.localdomain">>]).

%% ASCII whitespace trim by byte matching (no charlist round trip).
trim_binary(<<C, T/binary>>) when C =:= $\s; C =:= $\t; C =:= $\r; C =:= $\n ->
    trim_binary(T);
trim_binary(Bin) when is_binary(Bin) ->
    trim_trailing(Bin, byte_size(Bin)).

trim_trailing(Bin, 0) -> binary:part(Bin, 0, 0);
trim_trailing(Bin, N) ->
    case binary:at(Bin, N - 1) of
        C when C =:= $\s; C =:= $\t; C =:= $\r; C =:= $\n -> trim_trailing(Bin, N - 1);
        _ -> binary:part(Bin, 0, N)
    end.
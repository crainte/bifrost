%% Common Test suite for the DISTRIBUTED control plane, run against TWO REAL
%% Erlang nodes started with `peer`. This is deliberately not a single-node
%% suite: every cluster bug this project has hit was invisible on one node.
%%
%% bifrost_propagation_SUITE already pins the local write->event contract. This
%% suite pins the part that only exists across nodes:
%%   - Mnesia replicas actually land on every node (a node without a replica
%%     silently misses every broadcast).
%%   - A write on node A reaches node B's Rust, not just node B's Mnesia.
%%   - The cluster-wide fetch lock actually excludes a peer.
%%   - An HTTP 304 still feeds the peers that the lock excluded.
%%
%% Each test below names the real bug it catches. None of them can pass without
%% the production code doing the right thing across two nodes: they assert on
%% observable effects on the OTHER node, never on locally computed values.
%%
%% Requires a distributed CT node:
%%   rebar3 ct --sname ctrunner --suite=apps/bifrost/test/bifrost_cluster_SUITE
-module(bifrost_cluster_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([cluster_forms_replicas_on_every_node/1,
         blocklist_write_replicates_to_peer/1,
         peer_pushes_replicated_list_to_its_own_rust/1,
         blocklist_delete_replicates_to_peer/1,
         held_lock_stops_peer_from_fetching/1,
         concurrent_fetch_hits_upstream_once/1,
         not_modified_advances_freshness_and_feeds_peer/1,
         cache_propagation_reaches_peer_rust/1,
         cache_evict_reaches_peer_rust/1,
         config_reload_event_replicates_to_peer/1,
         singleton_job_elects_exactly_one_node/1,
         singleton_leadership_fails_over_when_holder_dies/1,
         domain_analyzer_scans_on_one_node_only/1,
         singleton_catalogue_matches_the_names_jobs_claim/1,
         srv_records_become_peer_node_names/1,
         explicit_seed_list_wins_over_dns_discovery/1,
         pause_on_one_node_pauses_the_peers_rust/1,
         pause_is_reapplied_when_a_peer_rehydrates/1,
         timed_pause_expires_on_every_node/1,
         dns_settings_publish_applies_on_peer_rust/1,
         stale_dns_settings_are_not_published_or_applied/1]).

%% spawned on the peer nodes, so they must be exported
-export([fake_rust_loop/1, lock_holder/2, leader_probe/3]).
%% test HTTP server internals, spawned by name
-export([http_server/4, http_accept/5, http_handle/5]).

-define(LIST_A, "ct-list-alpha").
-define(WAIT, 10000).

all() ->
    [cluster_forms_replicas_on_every_node,
     blocklist_write_replicates_to_peer,
     peer_pushes_replicated_list_to_its_own_rust,
     blocklist_delete_replicates_to_peer,
     held_lock_stops_peer_from_fetching,
     concurrent_fetch_hits_upstream_once,
     not_modified_advances_freshness_and_feeds_peer,
     cache_propagation_reaches_peer_rust,
     cache_evict_reaches_peer_rust,
     config_reload_event_replicates_to_peer,
     singleton_job_elects_exactly_one_node,
     singleton_leadership_fails_over_when_holder_dies,
     domain_analyzer_scans_on_one_node_only,
     singleton_catalogue_matches_the_names_jobs_claim,
     srv_records_become_peer_node_names,
     explicit_seed_list_wins_over_dns_discovery,
     pause_on_one_node_pauses_the_peers_rust,
     pause_is_reapplied_when_a_peer_rehydrates,
     timed_pause_expires_on_every_node,
     dns_settings_publish_applies_on_peer_rust,
     stale_dns_settings_are_not_published_or_applied].

%% ── Suite setup ───────────────────────────────────────────────

init_per_suite(Config) ->
    case node() of
        nonode@nohost ->
            {skip, "needs a distributed CT node: rebar3 ct --sname ctrunner"};
        _ ->
            PrivDir = ?config(priv_dir, Config),
            {PeerA, NodeA} = start_peer(bfnode1, PrivDir),
            {PeerB, NodeB} = start_peer(bfnode2, PrivDir),
            %% join_and_sync/0 elects the lowest-sorted CONNECTED node as table
            %% creator, and the CT node is connected to both peers. If the CT
            %% node sorted first it would be elected and never create anything,
            %% so fail loudly with an actionable message rather than time out.
            case hd(lists:sort([node(), NodeA, NodeB])) of
                NodeA -> ok;
                Other -> ct:fail({peers_must_sort_before_ct_node, Other, node()})
            end,
            form_cluster([NodeA, NodeB]),
            [{peers, [PeerA, PeerB]}, {nodes, [NodeA, NodeB]} | Config]
    end.

end_per_suite(Config) ->
    [catch peer:stop(P) || P <- proplists:get_value(peers, Config, [])],
    ok.

init_per_testcase(_Case, Config) ->
    flush_rust_msgs(),
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

%% Start a peer node carrying this run's code path and its own Mnesia dir.
start_peer(Name, PrivDir) ->
    MnesiaDir = filename:join(PrivDir, atom_to_list(Name)),
    ok = filelib:ensure_dir(filename:join(MnesiaDir, "keep")),
    Args = ["-setcookie", atom_to_list(erlang:get_cookie()),
            "-mnesia", "dir", "\"" ++ MnesiaDir ++ "\"",
            "-pa" | code:get_path()],
    {ok, Peer, Node} = peer:start(#{name => Name,
                                    host => inet_db:gethostname(),
                                    args => Args,
                                    wait_boot => 30000}),
    pong = net_adm:ping(Node),
    %% Production gets inets from bifrost_blocklist_manager:init/1. Tests that
    %% drive try_fetch/3 directly bypass that, so httpc needs starting here.
    {ok, _} = erpc:call(Node, application, ensure_all_started, [inets]),
    {Peer, Node}.

%% Form the cluster through the REAL production path (bifrost_mnesia:init_tables/0
%% -> bifrost_cluster:join_and_sync/0), concurrently on both nodes, which is how
%% pods actually boot and is the race the creator election exists to survive.
form_cluster(Nodes) ->
    Seeds = string:join([atom_to_list(N) || N <- Nodes], ","),
    [true = erpc:call(N, os, putenv, ["BIFROST_CLUSTER_NODES", Seeds]) || N <- Nodes],
    Self = self(),
    Pids = [spawn_link(fun() ->
                Self ! {done, N, catch erpc:call(N, bifrost_mnesia, init_tables, [], 120000)}
            end) || N <- Nodes],
    [receive {done, _, ok} -> ok
     after 120000 -> ct:fail(cluster_formation_timeout)
     end || _ <- Pids],
    ok.

%% ── Tests ─────────────────────────────────────────────────────

%% Every shared table must have a copy on EVERY node with the right storage
%% type. Mnesia only replicates a write to nodes holding a copy, so a node that
%% silently failed to add itself receives no broadcasts at all and drifts
%% forever. Catches regressions in bifrost_mnesia:ensure_table/add_local_copy
%% and bifrost_cluster:ensure_replicas.
cluster_forms_replicas_on_every_node(Config) ->
    [A, B] = ?config(nodes, Config),
    Expected = lists:sort([A, B]),
    lists:foreach(fun({Table, Storage}) ->
        lists:foreach(fun(N) ->
            Holders = lists:sort(erpc:call(N, mnesia, table_info, [Table, Storage])),
            ?assertEqual({Table, Storage, Expected}, {Table, Storage, Holders})
        end, [A, B])
    end, [{blocklist_cache, disc_copies},
          {cache_propagation, ram_copies},
          {cache_evict, ram_copies},
          {config_reload, ram_copies},
          {opconfig, disc_copies}]).

%% A blocklist cached on one node must be readable on the other. This is the
%% foundation the fetch lock stands on: the locked-out peer never fetches, so if
%% replication does not carry the data it has nothing.
blocklist_write_replicates_to_peer(Config) ->
    [A, B] = ?config(nodes, Config),
    Domains = [<<"repl-one.example">>, <<"repl-two.example">>],
    ok = erpc:call(A, bifrost_mnesia, write_cache, [?LIST_A, Domains, <<"\"etag-1\"">>]),
    ok = wait_until(fun() ->
        erpc:call(B, bifrost_mnesia, read_cache, [?LIST_A]) =/= not_found
    end),
    {ok, GotDomains, GotETag, FetchedAt} =
        erpc:call(B, bifrost_mnesia, read_cache, [?LIST_A]),
    ?assertEqual(Domains, GotDomains),
    ?assertEqual(<<"\"etag-1\"">>, GotETag),
    ?assert(FetchedAt > 0).

%% THE distribution contract. A write on node A must end up pushed into node B's
%% OWN Rust process, not merely into node B's Mnesia. Asserts on the actual IPC
%% messages B emits. If the blocklist_cache subscription or its handler breaks,
%% peers keep serving stale lists forever and only this test notices.
peer_pushes_replicated_list_to_its_own_rust(Config) ->
    [A, B] = ?config(nodes, Config),
    Fake = start_manager(B, self()),
    try
        Domains = [<<"push-one.example">>, <<"push-two.example">>],
        ok = erpc:call(A, bifrost_mnesia, write_cache, ["ct-push", Domains, <<"\"p\"">>]),
        Msgs = collect_rust_msgs(?WAIT),
        Loads = [M || M <- Msgs, maps:get(type, M, undefined) =:= <<"load_blocklist">>,
                      maps:get(list_id, M, undefined) =:= <<"ct-push">>],
        ?assertNotEqual([], Loads),
        Entries = lists:append([maps:get(entries, M) || M <- Loads]),
        ?assertEqual(lists:sort(Domains), lists:sort(Entries)),
        %% The list is rebuilt off to the side (begin) and swapped in whole
        %% (commit) AFTER every batch: a shrinking list cannot leave stale
        %% domains behind, and the old copy keeps blocking until the swap.
        Types = [maps:get(type, M) || M <- Msgs, maps:get(list_id, M, undefined) =:= <<"ct-push">>],
        ?assertEqual(<<"begin_blocklist">>, hd(Types)),
        ?assertEqual(<<"commit_blocklist">>, lists:last(Types)),
        ?assertNot(lists:member(<<"clear_blocklist">>, Types))
    after
        stop_manager(B, Fake)
    end.

%% Deleting a list on one node must clear it from the other node's Rust,
%% otherwise a disabled blocklist keeps blocking on every pod but one.
blocklist_delete_replicates_to_peer(Config) ->
    [A, B] = ?config(nodes, Config),
    ok = erpc:call(A, bifrost_mnesia, write_cache, ["ct-del", [<<"del.example">>], <<"\"d\"">>]),
    ok = wait_until(fun() ->
        erpc:call(B, bifrost_mnesia, read_cache, ["ct-del"]) =/= not_found
    end),
    Fake = start_manager(B, self()),
    try
        ok = erpc:call(A, bifrost_mnesia, delete_cache, ["ct-del"]),
        Msgs = collect_rust_msgs(?WAIT),
        ?assert(lists:any(fun(M) ->
            maps:get(type, M, undefined) =:= <<"clear_blocklist">> andalso
            maps:get(list_id, M, undefined) =:= <<"ct-del">>
        end, Msgs)),
        ?assertEqual(not_found, erpc:call(B, bifrost_mnesia, read_cache, ["ct-del"]))
    after
        stop_manager(B, Fake)
    end.

%% The cluster-wide fetch lock must exclude a peer. Deterministic version: node A
%% holds the very lock id the production path builds, then node B runs the real
%% try_fetch/3 and must not reach the upstream at all.
%%
%% This is the regression for two real bugs, both of which made the lock a no-op
%% with no error anywhere:
%%   - scoping the lock to [node()] instead of [node()|nodes()], which locks
%%     locally and therefore always succeeds;
%%   - using a constant LockRequesterId ({bifrost_fetch, Name}), since global
%%     grants a lock to identical requester ids by design.
%% Under either bug node B fetches and the upstream hit count becomes 1.
held_lock_stops_peer_from_fetching(Config) ->
    [A, B] = ?config(nodes, Config),
    {Srv, Url} = start_http("blocked.example\n", <<"\"lock\"">>, 0),
    try
        Holder = erpc:call(A, erlang, spawn, [?MODULE, lock_holder, [self(), "ct-locked"]]),
        receive {locked, Holder} -> ok
        after 5000 -> ct:fail(lock_holder_never_acquired)
        end,
        ok = erpc:call(B, bifrost_blocklist_manager, try_fetch, ["ct-locked", Url, undefined]),
        ?assertEqual(0, http_hits(Srv)),
        ?assertEqual(not_found, erpc:call(B, bifrost_mnesia, read_cache, ["ct-locked"])),
        Holder ! release,
        %% Once released the same node CAN fetch — proves the assertion above
        %% was the lock working, not the fetch being broken for another reason.
        ok = wait_until(fun() -> not erpc:call(A, erlang, is_process_alive, [Holder]) end),
        ok = erpc:call(B, bifrost_blocklist_manager, try_fetch, ["ct-locked", Url, undefined]),
        ?assertEqual(1, http_hits(Srv))
    after
        stop_http(Srv)
    end.

%% Same contract under a real race: both nodes refresh the same list at the same
%% moment. Exactly one HTTP request may reach the upstream, and BOTH nodes must
%% still end up with the data (the loser via replication). The server holds each
%% response open so the two attempts genuinely overlap.
concurrent_fetch_hits_upstream_once(Config) ->
    [A, B] = ?config(nodes, Config),
    {Srv, Url} = start_http("race-one.example\nrace-two.example\n", <<"\"race\"">>, 1500),
    try
        Expected = [<<"race-one.example">>, <<"race-two.example">>],
        Results = run_together(
            [{A, bifrost_blocklist_manager, try_fetch, ["ct-race", Url, undefined]},
             {B, bifrost_blocklist_manager, try_fetch, ["ct-race", Url, undefined]}]),
        %% Neither call may crash: with 0 lock retries both requesters get
        %% denied and this stays [ok,ok] while hits is 0, so assert both.
        ?assertEqual([ok, ok], Results),
        ?assertEqual(1, http_hits(Srv)),
        lists:foreach(fun(N) ->
            ok = wait_until(fun() ->
                erpc:call(N, bifrost_mnesia, read_cache, ["ct-race"]) =/= not_found
            end),
            {ok, Domains, _, _} = erpc:call(N, bifrost_mnesia, read_cache, ["ct-race"]),
            ?assertEqual({N, Expected}, {N, lists:sort(Domains)})
        end, [A, B])
    after
        stop_http(Srv)
    end.

%% An HTTP 304 means "your copy is current". The fetching node writes no new
%% domains, so without an explicit cache touch there is no Mnesia event and the
%% peers the lock excluded receive NOTHING, while fetched_at never advances and
%% the list stays permanently stale.
%%
%% Asserts both halves of the fix: freshness advances on BOTH nodes, and node B's
%% Rust is still fed. Deleting the touch_cache call makes this fail.
not_modified_advances_freshness_and_feeds_peer(Config) ->
    [A, B] = ?config(nodes, Config),
    ETag = <<"\"nm-1\"">>,
    Domains = [<<"nm-one.example">>],
    {Srv, Url} = start_http("nm-one.example\n", ETag, 0),
    try
        ok = erpc:call(A, bifrost_mnesia, write_cache, ["ct-nm", Domains, ETag]),
        ok = wait_until(fun() ->
            erpc:call(B, bifrost_mnesia, read_cache, ["ct-nm"]) =/= not_found
        end),
        set_fetched_at(A, "ct-nm", 0),
        ok = wait_until(fun() -> fetched_at(B, "ct-nm") =:= 0 end),

        Fake = start_manager(B, self()),
        try
            %% Passing the stored ETag makes the server answer 304.
            ok = erpc:call(A, bifrost_blocklist_manager, try_fetch, ["ct-nm", Url, ETag]),
            ?assertEqual(1, http_hits(Srv)),
            %% Freshness advanced on the fetching node...
            ok = wait_until(fun() -> fetched_at(A, "ct-nm") > 0 end),
            %% ...and replicated to the peer.
            ok = wait_until(fun() -> fetched_at(B, "ct-nm") > 0 end),
            %% Domains are untouched: a 304 must not clobber the cached list.
            {ok, Still, _, _} = erpc:call(B, bifrost_mnesia, read_cache, ["ct-nm"]),
            ?assertEqual(Domains, Still),
            %% And the peer's Rust was fed off the touch alone.
            Msgs = collect_rust_msgs(?WAIT),
            ?assert(lists:any(fun(M) ->
                maps:get(type, M, undefined) =:= <<"load_blocklist">> andalso
                maps:get(list_id, M, undefined) =:= <<"ct-nm">> andalso
                maps:get(entries, M, []) =:= Domains
            end, Msgs))
        after
            stop_manager(B, Fake)
        end
    after
        stop_http(Srv)
    end.

%% The transient query-cache bus: an entry cached on A must be pushed into B's
%% Rust as store_cache, with the response surviving the base64 round trip.
cache_propagation_reaches_peer_rust(Config) ->
    [A, B] = ?config(nodes, Config),
    Fake = start_manager(B, self()),
    try
        Wire = <<1, 2, 3, 250, 0, 255>>,
        Entry = #{<<"domain">> => <<"prop.example">>, <<"qtype">> => 28,
                  <<"response">> => base64:encode(Wire), <<"ttl">> => 120},
        ok = erpc:call(A, bifrost_mnesia, write_cache_entry, [Entry]),
        Msgs = collect_rust_msgs(?WAIT),
        Stores = [M || M <- Msgs, maps:get(type, M, undefined) =:= <<"store_cache">>],
        ?assertNotEqual([], Stores),
        [Store | _] = Stores,
        ?assertEqual(<<"prop.example">>, maps:get(domain, Store)),
        ?assertEqual(28, maps:get(qtype, Store)),
        ?assertEqual(120, maps:get(ttl, Store)),
        %% Round trips as bytes, not as a re-encoded string.
        ?assertEqual(Wire, base64:decode(maps:get(response, Store)))
    after
        stop_manager(B, Fake)
    end.

%% A cache bust on one node must evict on every node, or the busted domain keeps
%% being served from the peers' caches.
cache_evict_reaches_peer_rust(Config) ->
    [A, B] = ?config(nodes, Config),
    Fake = start_manager(B, self()),
    try
        ok = erpc:call(A, bifrost_mnesia, broadcast_evict, [<<"eviction.example">>]),
        Msgs = collect_rust_msgs(?WAIT),
        ?assert(lists:any(fun(M) ->
            maps:get(type, M, undefined) =:= <<"evict_cache">> andalso
            maps:get(domain, M, undefined) =:= <<"eviction.example">>
        end, Msgs))
    after
        stop_manager(B, Fake)
    end.

%% Operational config changes are routed by the `what` field. Verify the record
%% crosses the node boundary intact, since the peer handler dispatches on it and
%% a wrong/lost value sends the peer down the wrong re-push path (or none).
config_reload_event_replicates_to_peer(Config) ->
    [A, B] = ?config(nodes, Config),
    Ref = make_ref(),
    Self = self(),
    Sub = erpc:call(B, erlang, spawn, [fun() ->
        {ok, _} = mnesia:subscribe({table, config_reload, simple}),
        Self ! {subscribed, Ref},
        receive
            {mnesia_table_event, {write, {config_reload, What, Nonce}, _}} ->
                Self ! {reload, Ref, What, Nonce}
        after 15000 ->
                Self ! {reload, Ref, timeout, timeout}
        end
    end]),
    receive {subscribed, Ref} -> ok
    after 5000 -> ct:fail(peer_never_subscribed)
    end,
    ok = erpc:call(A, bifrost_mnesia, broadcast_config_reload, [blocklists]),
    receive
        {reload, Ref, What, Nonce} ->
            ?assertEqual(blocklists, What),
            ?assert(is_integer(Nonce))
    after ?WAIT ->
            exit(Sub, kill),
            ct:fail(config_reload_never_reached_peer)
    end.

%% bifrost_cluster:is_leader/1 is the single election shared by every
%% cluster-singleton job (ptr_warmer, domain_analyzer). Exactly one node may
%% win, or the job runs N times and multiplies load on whatever shared resource
%% it hits. Both probes race for the same name; global must pick one winner.
singleton_job_elects_exactly_one_node(Config) ->
    [A, B] = ?config(nodes, Config),
    Name = ct_singleton_elect,
    PA = spawn_probe(A, Name, a),
    PB = spawn_probe(B, Name, b),
    Results = [recv_leader(a), recv_leader(b)],
    try
        ?assertEqual(1, length([R || {_N, R} <- Results, R =:= true])),
        %% The winner is the node global reports as holding the name.
        [{WinnerNode, true}] = [R || {_, V} = R <- Results, V =:= true],
        ?assertEqual(WinnerNode, erpc:call(A, erlang, node, [global_whereis(A, Name)]))
    after
        stop_probe(PA), stop_probe(PB)
    end.

%% Registration is tied to the calling process, so when the holder dies global
%% frees the name and the next node's tick must be able to claim it. Without
%% that, losing the leader silently stops the job cluster-wide until a restart.
singleton_leadership_fails_over_when_holder_dies(Config) ->
    [A, B] = ?config(nodes, Config),
    Name = ct_singleton_failover,
    PA = spawn_probe(A, Name, a),
    ?assertEqual({A, true}, recv_leader(a)),
    %% B must not get it while A holds it.
    PB = spawn_probe(B, Name, b),
    ?assertEqual({B, false}, recv_leader(b)),
    stop_probe(PB),
    %% Kill the holder; global should release the name.
    stop_probe(PA),
    ok = wait_until(fun() -> global_whereis(A, Name) =:= undefined end),
    %% Now the survivor claims it.
    PB2 = spawn_probe(B, Name, b2),
    try
        ?assertEqual({B, true}, recv_leader(b2))
    after
        stop_probe(PB2)
    end.

%% Composition test: the election existing is not enough, domain_analyzer has to
%% actually USE it. Every node's analyzer reads the same shared query_log and
%% upserts the same rows, so an uncoordinated scan multiplies RDAP lookups and
%% header probes against third parties for identical domains.
%%
%% Drives the real GenServer on both nodes with the real `scan` message. Deleting
%% the is_leader/1 gate means nobody registers the name and whereis returns
%% undefined, so this fails.
domain_analyzer_scans_on_one_node_only(Config) ->
    [A, B] = ?config(nodes, Config),
    Started = [begin
                   {ok, Pid} = erpc:call(N, gen_server, start,
                                         [{local, bifrost_domain_analyzer},
                                          bifrost_domain_analyzer, [], []]),
                   {N, Pid}
               end || N <- [A, B]],
    try
        %% Tick both immediately rather than waiting out FIRST_SCAN_DELAY. The
        %% spawned scan itself will fail (no DB in this suite) but it is caught
        %% inside run_scan/0 — we assert on the election, not the scan result.
        [erpc:call(N, erlang, send, [Pid, scan]) || {N, Pid} <- Started],
        ok = wait_until(fun() ->
            global_whereis(A, bifrost_domain_analyzer_leader) =/= undefined
        end),
        Holder = global_whereis(A, bifrost_domain_analyzer_leader),
        HolderNode = erpc:call(A, erlang, node, [Holder]),
        ?assert(lists:member(HolderNode, [A, B])),
        %% Exactly one of the two analyzers holds it.
        ?assertEqual([HolderNode], [N || {N, Pid} <- Started, Pid =:= Holder])
    after
        [catch erpc:call(N, gen_server, stop, [Pid]) || {N, Pid} <- Started]
    end.

%% bifrost_cluster:singleton_jobs/0 is the single source the dashboard renders,
%% so a job whose ?LEADER name drifts from its catalogue entry would leave a
%% panel row permanently "unassigned" while the job actually runs — a silent lie
%% rather than a crash.
%%
%% The dashboard-shows-every-entry direction is structural (cluster_jobs/0 maps
%% over the catalogue), so asserting it would be a tautology. This asserts the
%% direction that CAN drift: start the real jobs and require that the global name
%% each one claims is the name the catalogue advertises. bus_sweep is claimed by
%% bifrost_cluster's own GenServer, which this suite does not run, so it is
%% checked for well-formedness only.
singleton_catalogue_matches_the_names_jobs_claim(Config) ->
    [A, _B] = ?config(nodes, Config),
    Catalogue = erpc:call(A, bifrost_cluster, singleton_jobs, []),
    ?assertNotEqual([], Catalogue),
    lists:foreach(fun({Name, GlobalName, Interval, Coordination}) ->
        ?assert(is_binary(Name)),
        ?assert(is_atom(GlobalName)),
        %% The UI derives "unassigned (ticks every N)" from this, so a zero or
        %% bogus interval would render a misleading panel.
        ?assert(is_integer(Interval) andalso Interval > 0),
        ?assert(is_binary(Coordination) andalso Coordination =/= <<>>)
    end, Catalogue),
    Names = [G || {_, G, _, _} <- Catalogue],
    ?assert(lists:member(bifrost_bus_sweep_leader, Names)),
    %% Each runnable job must claim exactly the name the catalogue advertises.
    lists:foreach(fun({Mod, Expected, Tick}) ->
        ?assert(lists:member(Expected, Names)),
        {ok, Pid} = erpc:call(A, gen_server, start, [{local, Mod}, Mod, [], []]),
        try
            erpc:call(A, erlang, send, [Pid, Tick]),
            ok = wait_until(fun() -> global_whereis(A, Expected) =:= Pid end)
        after
            catch erpc:call(A, gen_server, stop, [Pid])
        end
    end, [{bifrost_ptr_warmer, bifrost_ptr_warmer_leader, warm},
          {bifrost_domain_analyzer, bifrost_domain_analyzer_leader, scan}]).

%% is_leader/1 registers the CALLING process, so the probe must outlive the
%% call — an erpc:call process dies immediately and would free the name at once,
%% which is exactly the mistake production avoids by electing from the
%% long-lived GenServer.
leader_probe(Reply, Name, Tag) ->
    Reply ! {leader, Tag, node(), bifrost_cluster:is_leader(Name)},
    receive stop -> ok after 120000 -> ok end.

spawn_probe(Node, Name, Tag) ->
    erpc:call(Node, erlang, spawn, [?MODULE, leader_probe, [self(), Name, Tag]]).

stop_probe(Pid) ->
    Pid ! stop,
    ok.

recv_leader(Tag) ->
    receive {leader, Tag, Node, Result} -> {Node, Result}
    after 10000 -> ct:fail({leader_probe_timeout, Tag})
    end.

global_whereis(ViaNode, Name) ->
    erpc:call(ViaNode, global, whereis_name, [Name]).

%% Kubernetes publishes one SRV record per pod for each NAMED port on a headless
%% Service, and the SRV target is the pod's stable FQDN. Mapping those targets to
%% node names is what replaces hand-maintaining BIFROST_CLUSTER_NODES, so scaling
%% the StatefulSet needs no manifest edit.
%%
%% Synthetic records, deliberately: the live SRV round-trip needs a real cluster,
%% but the mapping is the part that can silently be wrong — a kept trailing dot,
%% a hardcoded node prefix, or failing to drop ourselves would each produce a
%% seed list that never connects, and the pod would just sit alone forever.
srv_records_become_peer_node_names(_Config) ->
    [Prefix | _] = string:split(atom_to_list(node()), "@"),
    Self = lists:nth(2, string:split(atom_to_list(node()), "@")),
    Records = [
        {0, 50, 4369, "bifrost-0.bifrost-headless.bifrost.svc.cluster.local."},
        {0, 50, 4369, "bifrost-1.bifrost-headless.bifrost.svc.cluster.local."},
        %% Duplicate target: k8s emits one SRV per named port, so a Service with
        %% both `epmd` and `erldist` can repeat a pod. Must not double-ping.
        {0, 50, 4369, "bifrost-1.bifrost-headless.bifrost.svc.cluster.local."},
        %% Our own pod is always in the Service's own records.
        {0, 50, 4369, Self}
    ],
    Got = bifrost_cluster:nodes_from_srv(Records),
    Expected = [list_to_atom(Prefix ++ "@bifrost-0.bifrost-headless.bifrost.svc.cluster.local"),
                list_to_atom(Prefix ++ "@bifrost-1.bifrost-headless.bifrost.svc.cluster.local")],
    ?assertEqual(lists:sort(Expected), lists:sort(Got)),
    ?assertNot(lists:member(node(), Got)).

%% docker-compose and any operator override rely on the explicit list still
%% taking precedence; DNS discovery must never quietly replace it.
explicit_seed_list_wins_over_dns_discovery(_Config) ->
    Saved = {os:getenv("BIFROST_CLUSTER_NODES"), os:getenv("BIFROST_CLUSTER_SERVICE")},
    try
        os:putenv("BIFROST_CLUSTER_SERVICE", "bifrost-headless.bifrost.svc.cluster.local"),
        os:putenv("BIFROST_CLUSTER_NODES", "bifrost@a, bifrost@b"),
        %% Explicit wins, whitespace trimmed, and no DNS query is made.
        ?assertEqual(['bifrost@a', 'bifrost@b'], bifrost_cluster:seeds()),
        %% Empty string is "unset", not "a seed named empty".
        os:putenv("BIFROST_CLUSTER_NODES", ""),
        os:unsetenv("BIFROST_CLUSTER_SERVICE"),
        ?assertEqual([], bifrost_cluster:seeds())
    after
        restore_env("BIFROST_CLUSTER_NODES", element(1, Saved)),
        restore_env("BIFROST_CLUSTER_SERVICE", element(2, Saved))
    end.

restore_env(Var, false) -> os:unsetenv(Var);
restore_env(Var, Val) -> os:putenv(Var, Val).

%% "Pause filtering" was node-local: behind a load balancer it paused one random
%% pod, the header showed a different answer per pod, and a Rust restart quietly
%% re-enabled filtering while the UI still said "paused". The pause is now
%% cluster state: set on A, it must reach B's OWN Rust and B's reported status.
pause_on_one_node_pauses_the_peers_rust(Config) ->
    [A, B] = ?config(nodes, Config),
    with_config_servers([A, B], fun() ->
        Fake = start_fake_rust(B),
        try
            ok = erpc:call(A, bifrost_config_server, set_protection, [false, 600]),
            ok = wait_until(fun() ->
                lists:any(fun(M) -> M =:= #{type => <<"set_protection">>, enabled => false} end,
                          collect_rust_msgs(500))
            end),
            {ok, #{enabled := false, until := Until}} =
                erpc:call(B, bifrost_config_server, get_protection, []),
            ?assert(is_integer(Until)),
            %% And back, from the OTHER side.
            ok = erpc:call(B, bifrost_config_server, set_protection, [true]),
            ok = wait_until(fun() ->
                {ok, #{enabled := E}} = erpc:call(A, bifrost_config_server, get_protection, []),
                E =:= true
            end)
        after
            stop_fake_rust(B, Fake)
        end
    end).

%% A restarted Rust process starts with filtering ON. Hydration must re-apply
%% the cluster's pause, or the UI says "paused" while DNS is filtering.
pause_is_reapplied_when_a_peer_rehydrates(Config) ->
    [A, B] = ?config(nodes, Config),
    with_settings_servers([A, B], ?config(priv_dir, Config), fun() ->
        ok = erpc:call(A, bifrost_config_server, set_protection, [false]),
        ok = wait_until(fun() ->
            {ok, #{enabled := E}} = erpc:call(B, bifrost_config_server, get_protection, []),
            E =:= false
        end),
        Fake = start_manager(B, self()),
        try
            flush_rust_msgs(),
            ok = erpc:call(B, bifrost_blocklist_manager, on_client_connected, []),
            Msgs = collect_rust_msgs(?WAIT),
            ?assert(lists:member(#{type => <<"set_protection">>, enabled => false}, Msgs))
        after
            stop_manager(B, Fake),
            ok = erpc:call(A, bifrost_config_server, set_protection, [true])
        end
    end).

timed_pause_expires_on_every_node(Config) ->
    [A, B] = ?config(nodes, Config),
    with_config_servers([A, B], fun() ->
        ok = erpc:call(A, bifrost_config_server, set_protection, [false, 1]),
        ok = wait_until(fun() ->
            {ok, #{enabled := E}} = erpc:call(B, bifrost_config_server, get_protection, []),
            E =:= false
        end),
        ok = wait_until(fun() ->
            {ok, #{enabled := E}} = erpc:call(B, bifrost_config_server, get_protection, []),
            E =:= true
        end, 5000)
    end).

dns_settings_publish_applies_on_peer_rust(Config) ->
    [A, B] = ?config(nodes, Config),
    with_settings_servers([A, B], ?config(priv_dir, Config), fun() ->
        Fake = start_fake_rust(B),
        try
            Snapshot = #{revision => 101, overrides => #{<<"cache">> =>
                #{<<"min_ttl">> => 0, <<"max_ttl">> => 900, <<"max_entries">> => 77}},
                ptr_ttl_seconds => 3600, retention_months => 4},
            ok = erpc:call(A, bifrost_dns_settings_server, publish, [Snapshot]),
            ok = wait_until(fun() ->
                lists:any(fun(#{type := <<"apply_dns_settings">>, revision := 101,
                                settings := #{<<"cache">> := #{<<"max_entries">> := 77}}}) -> true;
                             (_) -> false end, collect_rust_msgs(500))
            end),
            ok = wait_until(fun() ->
                maps:get(applied_revision, erpc:call(B, bifrost_dns_settings_server, status, [])) =:= 101
            end)
        after
            stop_fake_rust(B, Fake)
        end
    end).

stale_dns_settings_are_not_published_or_applied(Config) ->
    [A, B] = ?config(nodes, Config),
    with_settings_servers([A, B], ?config(priv_dir, Config), fun() ->
        ok = erpc:call(A, bifrost_dns_settings_server, publish,
                       [#{revision => 202, overrides => #{}, ptr_ttl_seconds => 21600,
                          retention_months => 6}]),
        ok = wait_until(fun() ->
            maps:get(desired_revision, erpc:call(B, bifrost_dns_settings_server, status, [])) =:= 202
        end),
        Fake = start_fake_rust(B),
        try
            ?assertEqual({error, stale}, erpc:call(A, bifrost_dns_settings_server, publish,
                [#{revision => 201, overrides => #{}, ptr_ttl_seconds => 60,
                   retention_months => 1}])),
            ?assertEqual([], [M || #{type := <<"apply_dns_settings">>} = M <- collect_rust_msgs(700)]),
            ?assertEqual(202, maps:get(desired_revision,
                erpc:call(B, bifrost_dns_settings_server, status, [])))
        after
            stop_fake_rust(B, Fake)
        end
    end).

with_settings_servers(Nodes, PrivDir, Fun) ->
    Path = filename:join(PrivDir, "dns_settings_config.erl"),
    ok = file:write_file(Path, <<"{upstreams, [[{address, \"192.0.2.53\"}, {port, 53}]]}.\n">>),
    [true = erpc:call(N, os, putenv, ["BIFROST_CONFIG_PATH", Path]) || N <- Nodes],
    with_config_servers(Nodes, fun() ->
        [{ok, _} = erpc:call(N, gen_server, start,
             [{local, bifrost_dns_settings_server}, bifrost_dns_settings_server, [], []])
         || N <- Nodes],
        try Fun()
        after
            [catch erpc:call(N, gen_server, stop, [bifrost_dns_settings_server]) || N <- Nodes]
        end
    end).

with_config_servers(Nodes, Fun) ->
    [{ok, _} = erpc:call(N, gen_server, start,
                         [{local, bifrost_config_server}, bifrost_config_server, [], []])
     || N <- Nodes],
    try Fun()
    after
        [catch erpc:call(N, gen_server, stop, [bifrost_config_server]) || N <- Nodes]
    end.

start_fake_rust(Node) ->
    Fake = erpc:call(Node, erlang, spawn, [?MODULE, fake_rust_loop, [self()]]),
    true = erpc:call(Node, erlang, register, [bifrost_socket_server, Fake]),
    flush_rust_msgs(),
    Fake.

stop_fake_rust(Node, Fake) ->
    catch erpc:call(Node, erlang, exit, [Fake, kill]),
    flush_rust_msgs(),
    ok.

%% ── Peer-side helpers (run ON the peer nodes) ─────────────────

%% Stands in for the Rust IPC socket: bifrost_socket_server:send_message/1 is a
%% gen_server:call to this registered name, so registering here captures exactly
%% what a node would have sent to its own Rust process.
fake_rust_loop(Collector) ->
    receive
        {'$gen_call', From, {send, Data}} ->
            Collector ! {rust_msg, node(), Data},
            gen_server:reply(From, ok),
            case Data of
                #{type := <<"apply_dns_settings">>, revision := R, fingerprint := F} ->
                    bifrost_dns_settings_server:handle_ack(fake_connection,
                        #{<<"type">> => <<"dns_settings_applied">>, <<"revision">> => R,
                          <<"fingerprint">> => F});
                _ -> ok
            end,
            fake_rust_loop(Collector);
        {'$gen_call', From, connection_id} ->
            gen_server:reply(From, fake_connection),
            fake_rust_loop(Collector);
        stop ->
            ok;
        _Other ->
            fake_rust_loop(Collector)
    end.

%% Holds the production fetch lock until told to release. Built via the exported
%% fetch_lock_id/0,1 so the test cannot drift from the real lock identity.
lock_holder(Reply, Name) ->
    LockId = bifrost_blocklist_manager:fetch_lock_id(Name),
    Nodes = bifrost_blocklist_manager:fetch_lock_nodes(),
    true = global:set_lock(LockId, Nodes, 0),
    Reply ! {locked, self()},
    receive
        release -> global:del_lock(LockId, Nodes)
    after 60000 -> global:del_lock(LockId, Nodes)
    end.

%% ── Manager + fake Rust lifecycle ─────────────────────────────

start_manager(Node, Collector) ->
    Fake = erpc:call(Node, erlang, spawn, [?MODULE, fake_rust_loop, [Collector]]),
    true = erpc:call(Node, erlang, register, [bifrost_socket_server, Fake]),
    {ok, _} = erpc:call(Node, gen_server, start,
                        [{local, bifrost_blocklist_manager}, bifrost_blocklist_manager, [], []]),
    Fake.

stop_manager(Node, Fake) ->
    catch erpc:call(Node, gen_server, stop, [bifrost_blocklist_manager]),
    catch erpc:call(Node, erlang, exit, [Fake, kill]),
    flush_rust_msgs(),
    ok.

collect_rust_msgs(Timeout) ->
    collect_rust_msgs(Timeout, []).

collect_rust_msgs(Timeout, Acc) ->
    receive
        {rust_msg, _Node, Data} -> collect_rust_msgs(300, [Data | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.

flush_rust_msgs() ->
    receive {rust_msg, _, _} -> flush_rust_msgs()
    after 0 -> ok
    end.

%% ── Mnesia helpers ────────────────────────────────────────────

fetched_at(Node, Name) ->
    case erpc:call(Node, mnesia, dirty_read, [blocklist_cache, Name]) of
        [Rec] -> element(5, Rec);
        [] -> undefined
    end.

set_fetched_at(Node, Name, Value) ->
    [Rec] = erpc:call(Node, mnesia, dirty_read, [blocklist_cache, Name]),
    ok = erpc:call(Node, mnesia, dirty_write, [setelement(5, Rec, Value)]).

%% ── Concurrency helper ────────────────────────────────────────

%% Fire the given MFAs on their nodes as simultaneously as we can: every worker
%% blocks on a barrier first, so the calls start together rather than in
%% sequence. Waits for all of them.
run_together(Calls) ->
    Self = self(),
    Pids = [spawn_link(fun() ->
                receive go -> ok end,
                Self ! {finished, self(), catch erpc:call(N, M, F, A, 60000)}
            end) || {N, M, F, A} <- Calls],
    [P ! go || P <- Pids],
    [receive {finished, P, R} -> R
     after 60000 -> ct:fail({run_together_timeout, P})
     end || P <- Pids].

%% ── Polling helper ────────────────────────────────────────────

wait_until(Fun) -> wait_until(Fun, ?WAIT).

wait_until(Fun, Timeout) when Timeout =< 0 ->
    case Fun() of
        true -> ok;
        _ -> ct:fail({wait_until_timeout, erlang:fun_info(Fun, name)})
    end;
wait_until(Fun, Timeout) ->
    case catch Fun() of
        true -> ok;
        _ -> timer:sleep(100), wait_until(Fun, Timeout - 100)
    end.

%% ── Minimal counting HTTP server ──────────────────────────────
%% Not a general server: it speaks just enough HTTP for httpc, counts requests,
%% honours If-None-Match so the 304 path is real, and can hold each response
%% open so a concurrent-fetch race genuinely overlaps.

start_http(Body, ETag, DelayMs) ->
    Bin = list_to_binary(Body),
    Srv = spawn_link(?MODULE, http_server, [self(), Bin, ETag, DelayMs]),
    receive
        {http_port, Srv, Port} ->
            {Srv, "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/list.txt"}
    after 5000 ->
        ct:fail(http_server_did_not_start)
    end.

stop_http(Srv) -> Srv ! stop, ok.

http_hits(Srv) ->
    Srv ! {count, self()},
    receive {count, N} -> N
    after 5000 -> ct:fail(http_count_timeout)
    end.

http_server(Owner, Body, ETag, DelayMs) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                     {ip, {127, 0, 0, 1}}, {backlog, 16}]),
    {ok, Port} = inet:port(LSock),
    Owner ! {http_port, self(), Port},
    Acceptor = spawn_link(?MODULE, http_accept, [self(), LSock, Body, ETag, DelayMs]),
    http_ctl(0, LSock, Acceptor).

http_ctl(N, LSock, Acceptor) ->
    receive
        hit -> http_ctl(N + 1, LSock, Acceptor);
        {count, From} -> From ! {count, N}, http_ctl(N, LSock, Acceptor);
        stop -> gen_tcp:close(LSock), exit(Acceptor, kill), ok
    end.

http_accept(Ctl, LSock, Body, ETag, DelayMs) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            Pid = spawn(?MODULE, http_handle, [Ctl, Sock, Body, ETag, DelayMs]),
            gen_tcp:controlling_process(Sock, Pid),
            http_accept(Ctl, LSock, Body, ETag, DelayMs);
        {error, _} ->
            ok
    end.

http_handle(Ctl, Sock, Body, ETag, DelayMs) ->
    Req = http_read(Sock, <<>>),
    Ctl ! hit,
    timer:sleep(DelayMs),
    Resp =
        case http_etag_matches(Req, ETag) of
            true ->
                [<<"HTTP/1.1 304 Not Modified\r\nETag: ">>, ETag,
                 <<"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n">>];
            false ->
                [<<"HTTP/1.1 200 OK\r\nETag: ">>, ETag,
                 <<"\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ">>,
                 integer_to_binary(byte_size(Body)), <<"\r\n\r\n">>, Body]
        end,
    gen_tcp:send(Sock, Resp),
    gen_tcp:close(Sock).

http_read(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        nomatch ->
            case gen_tcp:recv(Sock, 0, 10000) of
                {ok, Data} -> http_read(Sock, <<Acc/binary, Data/binary>>);
                {error, _} -> Acc
            end;
        _ ->
            Acc
    end.

http_etag_matches(Req, ETag) ->
    Lower = iolist_to_binary(string:lowercase(Req)),
    case binary:match(Lower, <<"if-none-match:">>) of
        nomatch -> false;
        _ -> binary:match(Req, ETag) =/= nomatch
    end.

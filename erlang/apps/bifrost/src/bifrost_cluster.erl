%% Cluster manager. Forms and maintains the distributed-Erlang + Mnesia cluster
%% across pods so the transient propagation buses (cache_evict, cache_propagation,
%% config_reload) and the blocklist_cache actually replicate cluster-wide.
%%
%% Seeds come from BIFROST_CLUSTER_NODES (comma-separated name@host). Joining is
%% resilient to boot order: we retry until a seed answers, then merge Mnesia and
%% ensure this node holds a copy of every shared table. A net_kernel monitor
%% re-runs the merge whenever a peer (re)connects, so pod churn self-heals.
%%
%% Single-node dev (env unset/empty): this is a no-op; the node runs its own
%% local Mnesia created by bifrost_mnesia:init_tables/0.
-module(bifrost_cluster).
-behaviour(gen_server).

-export([start_link/0, join_now/0, join_and_sync/0, members/0, is_leader/1,
         singleton_jobs/0, seeds/0, nodes_from_srv/1, clustered/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(RETRY_INTERVAL, 5000).   %% retry join every 5s until a seed connects
-define(BOOT_CONNECT_TIMEOUT, 30000). %% wait up to 30s at boot for peers
-define(BOOT_POLL, 1000).
-define(DNS_TIMEOUT, 2000).       %% headless-Service SRV lookup
-define(SWEEP_INTERVAL, 300000).  %% 5 min: bound the transient propagation buses
-define(SWEEP_LEADER, bifrost_bus_sweep_leader).

%% THE catalogue of cluster-singleton jobs. One source of truth: is_leader/1
%% callers use these global names and the dashboard renders this list, so adding
%% a singleton means adding one line HERE and nothing else. Deliberately static
%% rather than a self-registering registry: a job would then only appear after
%% its first tick, making "not yet ticked" indistinguishable from "missing" —
%% exactly the question the panel exists to answer. bifrost_cluster_SUITE asserts
%% that the names the real jobs claim at runtime are the names listed here.
%%
%% The interval is the job's own tick period, carried here ONLY so the UI can say
%% how long "unassigned" is expected to last after a boot. There is deliberately
%% no last-run heartbeat: holding the global name already proves the owning
%% process is alive, and every job re-arms its timer unconditionally, so a
%% heartbeat would tick happily while the actual work failed every time. Failing
%% work is what the error log is for.
-define(SINGLETON_JOBS, [
    {<<"ptr_warmer">>, bifrost_ptr_warmer_leader, 300,
     <<"global registered name; survivors reclaim on leader death">>},
    {<<"domain_analyzer">>, bifrost_domain_analyzer_leader, 900,
     <<"global registered name; next survivor's tick reclaims">>},
    {<<"bus_sweep">>, ?SWEEP_LEADER, ?SWEEP_INTERVAL div 1000,
     <<"clears the transient Mnesia propagation buses">>}
]).

%% [{Name, GlobalName, TickIntervalSeconds, CoordinationDescription}]
-spec singleton_jobs() -> [{binary(), atom(), pos_integer(), binary()}].
singleton_jobs() -> ?SINGLETON_JOBS.

%% No cached seed list: it is re-resolved per attempt (see seeds/0).
-record(state, {joined :: boolean()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Force an immediate join/replica-sync attempt.
join_now() ->
    gen_server:cast(?MODULE, join).

%% Current cluster membership (this node + connected peers).
members() ->
    [node() | nodes()].

%% Cluster-wide singleton election, shared by every recurring job that must run
%% on exactly ONE node (bifrost_ptr_warmer, bifrost_domain_analyzer).
%%
%% Use this for work that is a single indivisible sweep with no natural shard
%% key, where running it on N nodes just multiplies load on a shared resource.
%% Work that IS shardable (the per-list blocklist fetches) uses a per-resource
%% global:set_lock instead, so different nodes can process different resources
%% concurrently — see bifrost_blocklist_manager:try_fetch/4.
%%
%% The caller is the leader if it holds Name, or can claim it because nobody
%% does. global:register_name resolves races cluster-wide, so at most one node
%% ever wins. Registration is tied to the CALLING process and global frees the
%% name when that process dies, so the next survivor's tick claims it — call
%% this from the long-lived GenServer, never from a short-lived worker.
-spec is_leader(atom()) -> boolean().
is_leader(Name) ->
    case global:whereis_name(Name) of
        undefined -> global:register_name(Name, self()) =:= yes;
        Pid -> Pid =:= self()
    end.

%% Synchronous boot-time join, called from bifrost_mnesia:init_tables/0 BEFORE
%% any table is created. Connects to seeds, merges their schema, and decides
%% whether THIS node is the table creator or a joiner that must wait for the
%% creator's tables to appear. Prevents the "two nodes independently create the
%% same table -> merge_schema_failed" race by electing a single creator (the
%% lowest-sorted member). Bounded by BOOT_CONNECT_TIMEOUT; degrades to
%% single-node creator if no peers show up in time.
join_and_sync() ->
    %% Gate on whether clustering is CONFIGURED, not on seeds() being non-empty.
    %% With DNS discovery an empty resolve at this instant is a transient
    %% condition (kube-dns may not list every pod yet), and treating it as
    %% single-node here would make two pods both elect themselves table creator.
    case clustered() of
        false ->
            ok;  %% single-node: we are the creator
        true ->
            connect_until(now_ms() + ?BOOT_CONNECT_TIMEOUT),
            case nodes() of
                [] ->
                    logger:info("cluster: no peers at boot, creating tables solo"),
                    ok;
                Peers ->
                    _ = mnesia:change_config(extra_db_nodes, Peers),
                    Members = lists:sort([node() | Peers]),
                    Creator = hd(Members),
                    case node() =:= Creator of
                        true ->
                            logger:info("cluster: elected table creator among ~p", [Members]),
                            ok;
                        false ->
                            logger:info("cluster: joiner, waiting for ~p to create tables", [Creator]),
                            wait_for_tables(now_ms() + ?BOOT_CONNECT_TIMEOUT)
                    end
            end
    end.

%% Poll-connect until a seed answers or the deadline passes, RE-RESOLVING each
%% pass so a peer whose DNS record appears late is still found.
connect_until(Deadline) ->
    _ = [net_adm:ping(S) || S <- seeds()],
    case nodes() =/= [] orelse now_ms() >= Deadline of
        true -> ok;
        false -> timer:sleep(?BOOT_POLL), connect_until(Deadline)
    end.

%% Wait until the shared tables exist in the merged schema, then return so the
%% caller adds local copies.
wait_for_tables(Deadline) ->
    Tables = mnesia:system_info(tables),
    case lists:member(config_reload, Tables) orelse now_ms() >= Deadline of
        true -> ok;
        false -> timer:sleep(?BOOT_POLL), wait_for_tables(Deadline)
    end.

now_ms() -> erlang:monotonic_time(millisecond).

init([]) ->
    logger:info("~s started", [?MODULE]),
    %% Watch for peers coming and going so we can (re)sync replicas.
    net_kernel:monitor_nodes(true),
    self() ! join,
    erlang:send_after(?SWEEP_INTERVAL, self(), sweep_buses),
    {ok, #state{joined = false}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(join, State) ->
    {noreply, try_join(State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(join, State) ->
    State1 = try_join(State),
    %% Keep retrying while clustering is configured but unjoined. Gating on
    %% clustered() rather than a seed list matters for DNS discovery: an empty
    %% resolve is a reason to retry, not proof this is a single-node deployment.
    case State1#state.joined orelse not clustered() of
        true -> ok;
        false -> erlang:send_after(?RETRY_INTERVAL, self(), join)
    end,
    {noreply, State1};
handle_info({nodeup, Node}, State) ->
    logger:info("cluster: node up ~p, syncing Mnesia", [Node]),
    State1 = try_join(State),
    %% Partition heal: re-converge transient/derivable state. Mnesia does not
    %% auto-merge divergent table data after a netsplit, so re-push the (now
    %% re-merged) blocklist cache and operational config to the local Rust.
    case State1#state.joined of
        true -> resync_after_heal();
        false -> ok
    end,
    {noreply, State1};
handle_info({nodedown, Node}, State) ->
    logger:info("cluster: node down ~p", [Node]),
    {noreply, State};
handle_info(sweep_buses, State) ->
    %% cache_propagation and cache_evict are broadcast buses, not storage: a row
    %% exists only to make Mnesia replication fire a table event, and NOTHING
    %% ever reads them back. But nothing deleted the rows either, so they grew
    %% for the life of the node (one row per distinct domain forwarded/evicted,
    %% on every node) until a restart. Sweeping bounds them to one interval's
    %% worth. Already-delivered events are unaffected — they are messages in the
    %% subscribers' mailboxes, not reads of the table.
    %%
    %% Leader-only: clear_table replicates, so one node doing it is enough and N
    %% nodes doing it concurrently is just contention.
    case bifrost_cluster:is_leader(?SWEEP_LEADER) of
        true -> sweep_transient_buses();
        false -> ok
    end,
    erlang:send_after(?SWEEP_INTERVAL, self(), sweep_buses),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    net_kernel:monitor_nodes(false),
    ok.

%% ── Internal ─────────────────────────────────────────────────

%% clear_table is a replicated schema operation, so this empties the bus on
%% every node at once. Safe because neither table is ever read: see the
%% handle_info(sweep_buses, ...) note above.
sweep_transient_buses() ->
    lists:foreach(fun(Table) ->
        case mnesia:clear_table(Table) of
            {atomic, ok} -> ok;
            {aborted, Reason} ->
                logger:warning("could not sweep ~p: ~p", [Table, Reason])
        end
    end, [cache_propagation, cache_propagation_v2, cache_evict]).

%% Re-converge derivable state after a partition heal. Best-effort: reads the
%% re-merged Mnesia blocklist cache + Postgres operational config and re-pushes
%% to the local Rust. Safe to run repeatedly (idempotent pushes).
resync_after_heal() ->
    _ = catch bifrost_blocklist_manager:refresh_lists(),
    _ = catch bifrost_api_handler:push_manual_blocks(),
    _ = catch bifrost_api_handler:push_allowlist(),
    _ = catch bifrost_api_handler:push_rewrites(),
    _ = catch bifrost_api_handler:push_client_blocks(),
    ok.

%% Is clustering configured at all? Deliberately distinct from `seeds() =:= []`:
%% under DNS discovery an empty resolve is transient and must be retried, while
%% neither variable being set really is a single-node deployment.
clustered() ->
    env("BIFROST_CLUSTER_NODES") =/= undefined orelse
    env("BIFROST_CLUSTER_SERVICE") =/= undefined.

%% Seeds, in precedence order:
%%
%%   1. BIFROST_CLUSTER_NODES — explicit comma-separated name@host list. Used by
%%      docker-compose, and the escape hatch anywhere DNS discovery is wrong.
%%   2. BIFROST_CLUSTER_SERVICE — the headless Service FQDN. Kubernetes publishes
%%      one SRV record per pod for each NAMED port on a headless Service, and the
%%      SRV target is the pod's stable FQDN — exactly the host half of the node
%%      name. So the member list IS the Service: scaling the StatefulSet needs no
%%      manifest edit. Requires publishNotReadyAddresses on the Service, or peers
%%      cannot resolve each other before they are Ready.
%%   3. Neither set: single-node (dev).
%%
%% Resolved on EVERY join attempt, never cached: at boot DNS may not list every
%% pod yet (join retries until one answers), and a pod added later must be
%% discoverable without restarting anyone.
seeds() ->
    case env("BIFROST_CLUSTER_NODES") of
        undefined -> discover_seeds();
        Str -> without_self([list_to_atom(string:trim(S)) || S <- string:lexemes(Str, ",")])
    end.

discover_seeds() ->
    case env("BIFROST_CLUSTER_SERVICE") of
        undefined -> [];
        Service -> nodes_from_srv(srv_lookup(Service))
    end.

%% "_epmd._tcp.<service>" is the SRV name for the port named `epmd`. The port
%% number in the answer is irrelevant — only the targets matter.
srv_lookup(Service) ->
    Name = "_epmd._tcp." ++ Service,
    case inet_res:lookup(Name, in, srv, [], ?DNS_TIMEOUT) of
        [] ->
            logger:warning("cluster: ~s resolved no peers; staying single-node", [Name]),
            [];
        Records ->
            Records
    end.

%% Exported for the suite: this mapping is the part that can silently be wrong.
nodes_from_srv(Records) ->
    without_self([srv_node(Target) || {_Prio, _Weight, _Port, Target} <- Records]).

%% Reuse OUR OWN node prefix rather than hardcoding "bifrost", so renaming the
%% release cannot leave discovery quietly pointing at nodes that do not exist.
srv_node(Target) ->
    [Prefix | _] = string:split(atom_to_list(node()), "@"),
    list_to_atom(Prefix ++ "@" ++ string:trim(Target, trailing, ".")).

without_self(Nodes) -> lists:usort(Nodes) -- [node()].

env(Var) ->
    case os:getenv(Var) of
        false -> undefined;
        "" -> undefined;
        V -> V
    end.

%% Ping seeds, and if any peer is connected, merge Mnesia and ensure this node
%% holds a replica of every shared table.
try_join(State) ->
    _ = [net_adm:ping(S) || S <- seeds()],
    case nodes() of
        [] ->
            State#state{joined = false};
        Peers ->
            case mnesia:change_config(extra_db_nodes, Peers) of
                {ok, _} ->
                    ensure_replicas(),
                    logger:info("cluster: merged Mnesia with ~p", [Peers]),
                    State#state{joined = true};
                {error, Reason} ->
                    logger:warning("cluster: change_config failed: ~p", [Reason]),
                    State#state{joined = false}
            end
    end.

%% Ensure this node carries a copy of each shared table. blocklist_cache is
%% persistent (disc_copies); the propagation buses are transient (ram_copies).
%% A table only replicates its writes to nodes that hold a copy, so every node
%% MUST add itself as a copy holder or it silently misses broadcasts.
ensure_replicas() ->
    add_copy(blocklist_cache, disc_copies),
    add_copy(cache_propagation, ram_copies),
    add_copy(cache_propagation_v2, ram_copies),
    add_copy(cache_evict, ram_copies),
    add_copy(config_reload, ram_copies),
    add_copy(opconfig, disc_copies).

add_copy(Table, Storage) ->
    case mnesia:add_table_copy(Table, node(), Storage) of
        {atomic, ok} ->
            logger:info("cluster: added ~p copy of ~p", [Storage, Table]);
        {aborted, {already_exists, _, _}} ->
            ok;
        {aborted, {already_exists, _}} ->
            ok;
        {aborted, Reason} ->
            logger:warning("cluster: add_table_copy ~p: ~p", [Table, Reason])
    end.

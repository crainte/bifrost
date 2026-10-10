-module(bifrost_mnesia).

-export([init_tables/0, read_cache/1, write_cache/3, touch_cache/1, write_cache_entry/1, is_fresh/2, delete_cache/1, broadcast_evict/1, broadcast_config_reload/0, broadcast_config_reload/1]).

%% Exported record definition for use in other modules
-record(blocklist_cache, {
    list_id    :: binary(),
    domains    :: [binary()],
    etag       :: binary() | undefined,
    fetched_at :: non_neg_integer()
}).

%% ── Lifecycle ────────────────────────────────────────────────

%% Transient cache propagation bus — ram_copies only, entries are written
%% by the local socket_server when Rust reports a cache miss+forward,
%% then replicated to cluster nodes where the blocklist_manager pushes
%% them to the local Rust instance. Not retained after restart.
-record(cache_propagation, {
    domain   :: binary(),
    qtype    :: non_neg_integer(),
    response :: binary(),
    ttl      :: non_neg_integer()
}).

%% Transient cache eviction bus — ram_copies. A write here replicates to
%% cluster nodes, where blocklist_manager pushes evict_cache to local Rust.
%% nonce forces a distinct record each call so Mnesia set fires the event.
%% Policy-tagged cache bus. A new table rather than a changed record arity keeps
%% rolling upgrades safe: old nodes keep using cache_propagation, new routed
%% policies never feed old nodes.
-record(cache_propagation_v2, {
    key           :: {binary(), non_neg_integer(), binary(), binary()},
    response      :: binary(),
    ttl           :: non_neg_integer(),
    expires_at_ms :: non_neg_integer()
}).

-record(cache_evict, {
    domain :: binary(),
    nonce  :: integer()
}).

%% Transient operational-config reload bus — ram_copies. A write replicates to
%% cluster nodes, where blocklist_manager re-pushes manual_blocks/allowlist/
%% rewrites/client_blocks from the shared Postgres to its LOCAL Rust. Without
%% this, a config write behind a load balancer only reaches the node that
%% handled the request; peers keep stale state until restart. `what` names the
%% changed config; nonce forces a distinct record so the Mnesia set event fires.
-record(config_reload, {
    what  :: atom(),
    nonce :: integer()
}).

%% Last-known operational config (see bifrost_opconfig) and cluster-wide state
%% such as the filtering pause. disc_copies: must survive a full restart while
%% Postgres is unreachable, which is exactly when it is needed.
-record(opconfig, {
    key   :: atom(),
    value :: term()
}).


%% ── Table management ─────────────────────────────────────────
%%
%% Mnesia clustering protocol: independently-created tables cannot be merged
%% (different table cookies -> merge_schema_failed). So we NEVER pre-create a
%% shared table on a node that is joining an existing cluster. Instead:
%%   1. start Mnesia empty
%%   2. connect to peers and merge their schema (extra_db_nodes)
%%   3. for each table: if it already exists in the merged schema, just add a
%%      local copy; only the FIRST node (no peers) actually creates it.
%% Table cookies then match cluster-wide and replication works.

-define(SHARED_TABLES, [
    {blocklist_cache, disc_copies},
    {cache_propagation, ram_copies},
    {cache_propagation_v2, ram_copies},
    {cache_evict, ram_copies},
    {config_reload, ram_copies},
    {opconfig, disc_copies}
]).

%% Bound on waiting for local table copies to become readable at boot.
-define(TABLE_WAIT, 30000).

init_tables() ->
    %% Start Mnesia with a RAM schema (no create_schema) so a joining node can
    %% adopt the cluster's schema without a disc-cookie conflict. join_and_sync
    %% connects, elects a creator, and (for joiners) merges the cluster schema.
    %% Afterwards we persist the schema to disc so disc_copies survive restart.
    mnesia:start(),
    bifrost_cluster:join_and_sync(),
    _ = mnesia:change_table_copy_type(schema, node(), disc_copies),
    lists:foreach(fun({Table, Storage}) -> ensure_table(Table, Storage) end,
                  ?SHARED_TABLES),
    %% Adding a table copy is asynchronous: the copy is not readable the instant
    %% ensure_table/2 returns. Rust connects within milliseconds of boot and
    %% hydration immediately reads blocklist_cache, so without this the first
    %% read raced the schema merge and aborted with {no_exists, ...}. Bounded so
    %% a genuinely broken table cannot wedge startup forever.
    case mnesia:wait_for_tables([T || {T, _} <- ?SHARED_TABLES], ?TABLE_WAIT) of
        ok -> ok;
        {timeout, Late} -> logger:warning("Mnesia tables not ready in time: ~p", [Late]);
        {error, Reason} -> logger:warning("Mnesia wait_for_tables: ~p", [Reason])
    end,
    ok.

%% Create the table if it doesn't exist anywhere; otherwise (it came in via the
%% merged schema) add a local copy so this node receives replicated writes.
ensure_table(Table, Storage) ->
    case lists:member(Table, mnesia:system_info(tables)) of
        true ->
            add_local_copy(Table, Storage);
        false ->
            create_table(Table, Storage)
    end.

create_table(Table, Storage) ->
    Attrs = table_attributes(Table),
    case mnesia:create_table(Table, [
        {Storage, [node()]},
        {attributes, Attrs},
        {type, set}
    ]) of
        {atomic, ok} ->
            logger:info("created Mnesia table ~p", [Table]),
            ok;
        {aborted, {already_exists, _}} ->
            add_local_copy(Table, Storage);
        {aborted, Reason} ->
            logger:error("failed to create Mnesia table ~p: ~p", [Table, Reason]),
            error({mnesia_create_table_failed, Reason})
    end.

add_local_copy(Table, Storage) ->
    case mnesia:add_table_copy(Table, node(), Storage) of
        {atomic, ok} ->
            logger:info("added local ~p copy of ~p", [Storage, Table]);
        {aborted, {already_exists, _, _}} -> ok;
        {aborted, {already_exists, _}} -> ok;
        {aborted, Reason} ->
            logger:warning("add_table_copy ~p: ~p", [Table, Reason])
    end,
    %% Ensure schema is on disc so disc_copies survive restart on first node.
    ok.

table_attributes(blocklist_cache)   -> record_info(fields, blocklist_cache);
table_attributes(cache_propagation) -> record_info(fields, cache_propagation);
table_attributes(cache_propagation_v2) -> record_info(fields, cache_propagation_v2);
table_attributes(cache_evict)       -> record_info(fields, cache_evict);
table_attributes(config_reload)     -> record_info(fields, config_reload);
table_attributes(opconfig)          -> record_info(fields, opconfig).

%% ── Cache read / write ───────────────────────────────────────

%% Defensive against {aborted, {no_exists, _}}: a cache read must never crash a
%% caller just because the local replica is not up yet (node still merging the
%% cluster schema). Absent table reads exactly like an absent entry.
read_cache(ListId) ->
    try mnesia:dirty_read(blocklist_cache, ListId) of
        [#blocklist_cache{domains = Domains, etag = ETag, fetched_at = FetchedAt}]
          when is_list(Domains), length(Domains) > 0 ->
            {ok, Domains, ETag, FetchedAt};
        _ ->
            not_found
    catch
        _:_ -> not_found
    end.
write_cache(ListId, Domains, ETag) ->
    Record = #blocklist_cache{
        list_id    = ListId,
        domains    = Domains,
        etag       = ETag,
        fetched_at = erlang:system_time(second)
    },
    mnesia:dirty_write(Record).

%% Confirm an existing cached list as current (HTTP 304) without refetching:
%% rewrite it with a new fetched_at. The write is deliberate, not incidental —
%% it fires the blocklist_cache table event on every replica, which is how a
%% node that skipped the fetch on the cluster lock gets the list pushed to its
%% local Rust.
touch_cache(ListId) ->
    case mnesia:dirty_read(blocklist_cache, ListId) of
        [Record] ->
            mnesia:dirty_write(Record#blocklist_cache{
                fetched_at = erlang:system_time(second)
            });
        [] ->
            ok
    end.

%% ── Cache propagation ─────────────────────────────────────────

write_cache_entry(#{<<"domain">> := Domain, <<"qtype">> := Qtype, <<"response">> := ResponseB64,
                    <<"ttl">> := TTL, <<"fingerprint">> := Fingerprint,
                    <<"variant">> := Variant, <<"expires_at_ms">> := Expires})
  when is_binary(Domain), byte_size(Domain) =< 253, is_integer(Qtype), Qtype >= 0, Qtype =< 65535,
       is_binary(ResponseB64), byte_size(ResponseB64) =< 87382, is_integer(TTL), TTL > 0,
       is_binary(Fingerprint), byte_size(Fingerprint) =< 128, is_binary(Variant),
       byte_size(Variant) =< 8, is_integer(Expires) ->
    mnesia:dirty_write(#cache_propagation_v2{
        key = {Domain, Qtype, Fingerprint, Variant},
        response = base64:decode(ResponseB64), ttl = TTL, expires_at_ms = Expires}),
    ok;
write_cache_entry(#{<<"domain">> := Domain, <<"qtype">> := Qtype, <<"response">> := ResponseB64, <<"ttl">> := TTL}) ->
    Response = base64:decode(ResponseB64),
    mnesia:dirty_write(#cache_propagation{
        domain   = Domain,
        qtype    = Qtype,
        response = Response,
        ttl      = TTL
    }),
    ok;
write_cache_entry(_) ->
    ok.

%% Broadcast a cache-bust for Domain to all cluster nodes (incl. self).
broadcast_evict(Domain) when is_binary(Domain) ->
    mnesia:dirty_write(#cache_evict{
        domain = Domain,
        nonce  = erlang:unique_integer([monotonic])
    }),
    ok.

%% Broadcast an operational-config reload to all cluster nodes (incl. self),
%% so every node re-pushes the changed config from Postgres to its local Rust.
%% `what` routes the peer handler: `operational` = manual blocks/allow/rewrites/
%% client blocks; `blocklists` = enable/disable/add/delete of URL blocklists.
broadcast_config_reload() ->
    broadcast_config_reload(operational).

broadcast_config_reload(What) when is_atom(What) ->
    mnesia:dirty_write(#config_reload{
        what  = What,
        nonce = erlang:unique_integer([monotonic])
    }),
    ok.

%% ── Helper ───────────────────────────────────────────────────

is_fresh(FetchedAt, MaxAgeSeconds) ->
    erlang:system_time(second) - FetchedAt < MaxAgeSeconds.

delete_cache(ListId) ->
    mnesia:dirty_delete(blocklist_cache, ListId).

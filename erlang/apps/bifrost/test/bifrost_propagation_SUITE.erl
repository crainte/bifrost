%% Common Test suite for the Mnesia propagation buses that make cluster-wide
%% config/cache changes work behind a load balancer. These verify the ACTUAL
%% contract bifrost_blocklist_manager relies on: a broadcast_* call produces a
%% Mnesia table write event that a subscriber receives — with the right shape and
%% routing field. If this contract breaks, cross-node propagation silently stops,
%% so a real bug fails here.
%%
%% Runs single-node (BIFROST_CLUSTER_NODES unset): Mnesia replication across nodes
%% is verified live on the multi-pod cluster; here we pin the local write->event
%% behavior that replication is built on.
-module(bifrost_propagation_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([config_reload_operational_fires_event/1,
         config_reload_blocklists_routes_by_what/1,
         cache_evict_fires_event/1,
         evict_nonce_makes_distinct_events/1,
         cache_write_and_read_roundtrip/1]).

all() ->
    [config_reload_operational_fires_event,
     config_reload_blocklists_routes_by_what,
     cache_evict_fires_event,
     evict_nonce_makes_distinct_events,
     cache_write_and_read_roundtrip].

init_per_suite(Config) ->
    %% Isolated Mnesia dir; single-node (no cluster seeds).
    os:unsetenv("BIFROST_CLUSTER_NODES"),
    application:set_env(mnesia, dir, "/tmp/bifrost_prop_ct"),
    os:cmd("rm -rf /tmp/bifrost_prop_ct"),
    ok = bifrost_mnesia:init_tables(),
    Config.

end_per_suite(_Config) ->
    mnesia:stop(),
    os:cmd("rm -rf /tmp/bifrost_prop_ct"),
    ok.

%% broadcast_config_reload/0 (operational) writes a config_reload row; a
%% subscriber gets a write event carrying what=operational — exactly what the
%% blocklist_manager matches to re-push manual blocks/allow/rewrites/client blocks.
config_reload_operational_fires_event(_Config) ->
    subscribe(config_reload),
    ok = bifrost_mnesia:broadcast_config_reload(),
    Event = recv_event(config_reload),
    ?assertMatch({write, {config_reload, operational, _Nonce}, _}, Event),
    unsubscribe(config_reload).

%% broadcast_config_reload(blocklists) carries what=blocklists, so the manager
%% routes it to the blocklist re-sync path rather than the operational one.
config_reload_blocklists_routes_by_what(_Config) ->
    subscribe(config_reload),
    ok = bifrost_mnesia:broadcast_config_reload(blocklists),
    {write, {config_reload, What, _Nonce}, _} = recv_event(config_reload),
    ?assertEqual(blocklists, What),
    unsubscribe(config_reload).

%% broadcast_evict/1 writes a cache_evict row; subscriber gets the domain, which
%% the manager forwards to Rust as an evict_cache message.
cache_evict_fires_event(_Config) ->
    subscribe(cache_evict),
    ok = bifrost_mnesia:broadcast_evict(<<"evil.example">>),
    {write, {cache_evict, Domain, _Nonce}, _} = recv_event(cache_evict),
    ?assertEqual(<<"evil.example">>, Domain),
    unsubscribe(cache_evict).

%% cache_evict is a `set` table keyed by domain, so evicting the SAME domain
%% twice must still fire two distinct events — the nonce guarantees a new record
%% each time (otherwise a repeat evict would be swallowed by Mnesia dedup).
evict_nonce_makes_distinct_events(_Config) ->
    subscribe(cache_evict),
    ok = bifrost_mnesia:broadcast_evict(<<"repeat.example">>),
    {write, {cache_evict, _, N1}, _} = recv_event(cache_evict),
    ok = bifrost_mnesia:broadcast_evict(<<"repeat.example">>),
    {write, {cache_evict, _, N2}, _} = recv_event(cache_evict),
    ?assertNotEqual(N1, N2),
    unsubscribe(cache_evict).

%% The blocklist cache write/read path (used for cross-node blocklist replication)
%% round-trips domains + etag.
cache_write_and_read_roundtrip(_Config) ->
    ok = bifrost_mnesia:write_cache("test-list", [<<"a.com">>, <<"b.com">>], <<"etag123">>),
    {ok, Domains, ETag, FetchedAt} = bifrost_mnesia:read_cache("test-list"),
    ?assertEqual([<<"a.com">>, <<"b.com">>], Domains),
    ?assertEqual(<<"etag123">>, ETag),
    ?assert(is_integer(FetchedAt)),
    ?assertEqual(not_found, bifrost_mnesia:read_cache("no-such-list")).

%% ── helpers ───────────────────────────────────────────────────

subscribe(Table) ->
    {ok, _} = mnesia:subscribe({table, Table, simple}).

unsubscribe(Table) ->
    mnesia:unsubscribe({table, Table, simple}).

%% Wait for the next mnesia_table_event for Table, stripping the ActivityId.
recv_event(Table) ->
    receive
        {mnesia_table_event, {write, Rec, _Act} = _E} when element(1, Rec) =:= Table ->
            {write, Rec, ignored}
    after 5000 ->
        ct:fail({no_event, Table})
    end.

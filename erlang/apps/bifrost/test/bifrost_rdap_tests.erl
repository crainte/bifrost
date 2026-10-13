%% Pure parts of bifrost_rdap: the per-registry pacer, the fill-queue admission,
%% and failure classification. The DB-backed claim/store/retry behaviour is in
%% bifrost_rdap_cache_SUITE against real Postgres.
-module(bifrost_rdap_tests).
-include_lib("eunit/include/eunit.hrl").

%% ── pacer ────────────────────────────────────────────────────

first_request_to_a_registry_goes_immediately_test() ->
    ?assertMatch({ok, 0, _}, bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, #{})).

second_request_to_same_registry_waits_one_interval_test() ->
    {ok, 0, P1} = bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, #{}),
    {ok, W2, P2} = bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, P1),
    ?assert(W2 >= 1000),
    %% Slots queue up rather than collapsing onto the same instant.
    {ok, W3, _} = bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, P2),
    ?assert(W3 >= W2 + 1000).

slot_frees_once_the_interval_has_passed_test() ->
    {ok, 0, P1} = bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, #{}),
    ?assertMatch({ok, 0, _}, bifrost_rdap:reserve("rdap.nic.io", 5000, 30000, P1)).

registries_are_paced_independently_test() ->
    {ok, 0, P1} = bifrost_rdap:reserve("rdap.nic.io", 1000, 30000, #{}),
    ?assertMatch({ok, 0, _}, bifrost_rdap:reserve("rdap.verisign.com", 1000, 30000, P1)).

wait_beyond_the_limit_is_refused_without_reserving_test() ->
    P = bifrost_rdap:push_back("rdap.nic.io", 120, 0, #{}),
    ?assertEqual(busy, bifrost_rdap:reserve("rdap.nic.io", 0, 30000, P)),
    %% A refused caller must not push everyone else further out.
    ?assertMatch({ok, 0, _}, bifrost_rdap:reserve("rdap.nic.io", 120000, 30000, P)).

rate_limit_pushes_the_whole_registry_out_test() ->
    P = bifrost_rdap:push_back("rdap.nic.io", 60, 1000, #{}),
    ?assertMatch({ok, 60000, _}, bifrost_rdap:reserve("rdap.nic.io", 1000, 90000, P)),
    %% Never pulls a later reservation earlier.
    P2 = bifrost_rdap:push_back("rdap.nic.io", 1, 1000, P),
    ?assertEqual(P, P2).

%% ── fill queue ───────────────────────────────────────────────

admit_dedupes_queued_and_in_flight_test() ->
    {ok, Q1, M1} = bifrost_rdap:admit(<<"a.com">>, queue:new(), #{}, 10),
    ?assertEqual(duplicate, bifrost_rdap:admit(<<"a.com">>, Q1, M1, 10)),
    %% In flight = in Members but no longer queued: still a duplicate.
    ?assertEqual(duplicate, bifrost_rdap:admit(<<"a.com">>, queue:new(), M1, 10)).

admit_drops_beyond_the_cap_test() ->
    {ok, Q1, M1} = bifrost_rdap:admit(<<"a.com">>, queue:new(), #{}, 1),
    ?assertEqual(full, bifrost_rdap:admit(<<"b.com">>, Q1, M1, 1)).

%% ── classification ───────────────────────────────────────────

classify_test_() ->
    R = fun(Code, Hdrs) -> {ok, {{"HTTP/1.1", Code, ""}, Hdrs, "{}"}} end,
    [?_assertEqual({ok, "{}"}, bifrost_rdap:classify(R(200, []))),
     ?_assertEqual({final, not_found}, bifrost_rdap:classify(R(404, []))),
     ?_assertEqual({transient, rate_limited, 120},
                   bifrost_rdap:classify(R(429, [{"retry-after", "120"}]))),
     ?_assertEqual({transient, rate_limited, undefined},
                   bifrost_rdap:classify(R(429, [{"retry-after", "Wed, 21 Oct 2015 07:28:00 GMT"}]))),
     ?_assertEqual({transient, {http, 503}, 30},
                   bifrost_rdap:classify(R(503, [{"retry-after", " 30 "}]))),
     ?_assertEqual({transient, {http, 500}, undefined}, bifrost_rdap:classify(R(500, []))),
     ?_assertEqual({transient, request_failed, undefined},
                   bifrost_rdap:classify({error, timeout}))].

registered_on_parses_rdap_event_dates_test() ->
    ?assertEqual({2024, 1, 15}, bifrost_rdap:registered_on(<<"2024-01-15T00:00:00Z">>)),
    ?assertEqual(undefined, bifrost_rdap:registered_on(undefined)),
    ?assertEqual(undefined, bifrost_rdap:registered_on(<<"garbage">>)),
    ?assertEqual(undefined, bifrost_rdap:registered_on(<<"2024-13-45T00:00:00Z">>)).

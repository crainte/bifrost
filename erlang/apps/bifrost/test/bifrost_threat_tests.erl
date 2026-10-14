-module(bifrost_threat_tests).
-include_lib("eunit/include/eunit.hrl").

special_use_names_are_not_eligible_test() ->
    Rejected = [
        <<"1.10.10.10.in-addr.arpa">>,
        <<"1.10.10.10.IN-ADDR.ARPA">>,
        <<"1.0.0.0.0.0.0.0.ip6.arpa">>,
        <<"service.internal">>,
        <<"printer.local">>,
        <<"router.home">>,
        <<"host.lan">>,
        <<"example.test">>,
        <<"single-label">>
    ],
    [?assertNot(bifrost_api_handler:threat_eligible_domain(D)) || D <- Rejected].

public_hostnames_are_eligible_test() ->
    Accepted = [
        <<"example.com">>,
        <<"malicious-id.execute-api.us-west-2.amazonaws.com">>,
        <<"1.ads.example.xyz">>
    ],
    [?assert(bifrost_api_handler:threat_eligible_domain(D)) || D <- Accepted].

analyzer_keeps_exact_hostnames_test() ->
    A = <<"malicious-a.execute-api.us-west-2.amazonaws.com">>,
    B = <<"malicious-b.execute-api.us-west-2.amazonaws.com">>,
    Candidates = bifrost_domain_analyzer:rank_candidates([{A, 12}, {B, 11}]),
    ?assertEqual(lists:sort([A, B]), lists:sort([maps:get(domain, C) || C <- Candidates])),
    ?assertNot(lists:member(<<"amazonaws.com">>, [maps:get(domain, C) || C <- Candidates])).

analyzer_excludes_reverse_dns_test() ->
    ?assertEqual([], bifrost_domain_analyzer:rank_candidates([
        {<<"1.10.10.10.in-addr.arpa">>, 1000},
        {<<"1.0.0.0.0.0.0.0.ip6.arpa">>, 1000}
    ])).

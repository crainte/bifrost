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

campaign_key_requires_marker_label_test() ->
    ?assertEqual({<<"site">>, <<"447">>},
                 bifrost_threat_campaigns:campaign_key(<<"447.LindseyBlog.site">>)),
    ?assertEqual({<<"site">>, <<"1xx">>},
                 bifrost_threat_campaigns:campaign_key(<<"1xx.alyssablog.site">>)),
    [?assertEqual(none, bifrost_threat_campaigns:campaign_key(D))
     || D <- [<<"api.firwinds.site">>, <<"447.site">>, <<"x1.blog.site">>,
              <<"447.this-url-does-not-exist.invalid">>]].

campaigns_group_only_repeated_patterns_test() ->
    C = fun(D, H) -> #{domain => D, score => 4, hits => H} end,
    [Campaign] = bifrost_threat_campaigns:group([
        C(<<"447.a.site">>, 6), C(<<"447.b.site">>, 2), C(<<"447.c.site">>, 4),
        C(<<"1xx.a.site">>, 2), C(<<"1xx.b.site">>, 2),
        C(<<"api.a.site">>, 12)]),
    ?assertMatch(#{pattern := <<"447.*.site">>, domain_count := 3, queries := 12,
                   domains := [<<"447.a.site">>, <<"447.c.site">>, <<"447.b.site">>]},
                 Campaign).

campaign_dismissal_is_validated_test() ->
    ?assertEqual({ok, #{tld => <<"site">>, leading_label => <<"447">>,
                        client_ip => {10, 10, 10, 250}, days => 30}},
                 bifrost_threat_campaigns:validate_dismissal(
                     #{<<"tld">> => <<"SITE">>, <<"leading_label">> => <<"447">>,
                       <<"client_ip">> => <<"10.10.10.250">>})),
    ?assertMatch({ok, #{client_ip := null, days := 7}},
                 bifrost_threat_campaigns:validate_dismissal(
                     #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"1xx">>,
                       <<"client_ip">> => null, <<"days">> => 7})),
    [?assertMatch({error, _}, bifrost_threat_campaigns:validate_dismissal(B))
     || B <- [#{<<"tld">> => <<"site">>, <<"leading_label">> => <<"api">>},
              #{<<"tld">> => <<"s'te">>, <<"leading_label">> => <<"447">>},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"days">> => 0},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"days">> => 366},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"client_ip">> => <<"nope">>},
              #{<<"tld">> => <<"site">>}]].

analyzer_excludes_reverse_dns_test() ->
    ?assertEqual([], bifrost_domain_analyzer:rank_candidates([
        {<<"1.10.10.10.in-addr.arpa">>, 1000},
        {<<"1.0.0.0.0.0.0.0.ip6.arpa">>, 1000}
    ])).

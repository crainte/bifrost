-module(bifrost_threat_tests).
-include_lib("eunit/include/eunit.hrl").

special_use_names_are_not_eligible_test() ->
    Rejected = [
        <<"1.10.10.10.in-addr.arpa">>,
        <<"1.10.10.10.IN-ADDR.ARPA">>,
        <<"1.0.0.0.0.0.0.0.ip6.arpa">>,
        <<"in-addr.arpa">>,
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

%% ── scoring ───────────────────────────────────────────────────

lexical(D) ->
    bifrost_api_handler:score_candidate(D, 100, #{}).

qualifies(D) ->
    bifrost_api_handler:qualifies(lexical(D)).

%% Sharded infrastructure is ONE fact (a leading number), however deep it is.
numbered_shards_alone_do_not_qualify_test() ->
    [?assertNot(qualifies(D), D)
     || D <- [<<"0.pool.ntp.org">>, <<"1.cn.pool.ntp.org">>, <<"2.android.pool.ntp.org">>,
              <<"0.gravatar.com">>, <<"3.gifteddonut.com">>,
              <<"3.au.download.windowsupdate.com">>]],
    ?assertEqual([], bifrost_domain_analyzer:rank_candidates(
                       [{<<"0.pool.ntp.org">>, 5000}, {<<"0.gravatar.com">>, 5000}])).

depth_does_not_stack_with_numbered_label_test() ->
    #{score := S, reasons := R} = lexical(<<"0.datadog.pool.ntp.org">>),
    ?assertEqual(3, S),
    ?assertEqual([<<"numbered_subdomain">>], R),
    %% Without the number, depth is still its own signal.
    #{reasons := R2} = lexical(<<"a.b.c.d.example.com">>),
    ?assert(lists:member(<<"deep_subdomains">>, R2)).

two_independent_signals_are_required_test() ->
    %% numbered (3) + generic hyphen (1): two signals, score 4.
    C = lexical(<<"4.stg.content-loader.com">>),
    ?assertMatch(#{score := 4}, C),
    ?assert(bifrost_api_handler:qualifies(C)),
    %% Score alone is not enough.
    ?assertNot(bifrost_api_handler:qualifies(
                 #{domain => <<"x.example.com">>, score => 9, reasons => [<<"numbered_subdomain">>]})),
    %% Two signals below the threshold are not enough either.
    ?assertNot(bifrost_api_handler:qualifies(
                 #{domain => <<"x.example.com">>, score => 2,
                   reasons => [<<"hyphenated_generic">>, <<"newly_seen">>]})).

burst_is_gone_and_hyphen_scores_one_test() ->
    #{score := S, reasons := R} = bifrost_api_handler:score_candidate(<<"cdn-sync.example.com">>, 1000000, #{}),
    ?assertNot(lists:member(<<"burst_hits">>, R)),
    ?assertEqual([<<"hyphenated_generic">>], R),
    ?assertEqual(1, S).

negative_terms_and_tags_are_not_signals_test() ->
    ?assertEqual(0, bifrost_api_handler:signal_weight(
                      [<<"widespread">>, <<"rdap:established">>, <<"single_client">>,
                       <<"no_csp">>, <<"permissive_cors">>, <<"rdap:no_transfer_lock">>,
                       <<"rdap:privacy_protected">>])),
    ?assertEqual(1, bifrost_api_handler:signal_weight([<<"numbered_subdomain">>,
                                                       <<"numbered_subdomain">>])).

cname_to_blocked_alone_qualifies_test() ->
    Ctx = bifrost_threat_context:combine(#{clients => 2, widespread_threshold => 5,
                                           blocked_cnames => [<<"t.tracker.net">>]}),
    C = bifrost_api_handler:score_candidate(<<"metrics.example.com">>, 10, Ctx),
    ?assertMatch(#{score := 6, reasons := [<<"cname_to_blocked:t.tracker.net">>]}, C),
    ?assert(bifrost_api_handler:qualifies(C)),
    %% Popularity and registration age cannot outweigh it.
    Wide = bifrost_threat_context:combine(#{clients => 40, widespread_threshold => 5,
                                            blocked_cnames => [<<"t.tracker.net">>]}),
    Old = bifrost_api_handler:score_candidate(<<"metrics.example.com">>, 10, Wide),
    Discounted = Old#{score => maps:get(score, Old) + bifrost_api_handler:score_rdap(#{age_days => 5000}),
                      reasons => maps:get(reasons, Old) ++ [<<"rdap:established">>]},
    ?assertEqual(1, maps:get(score, Discounted)),
    ?assert(bifrost_api_handler:qualifies(Discounted)),
    %% Still never for special-use names.
    ?assertNot(bifrost_api_handler:qualifies(Discounted#{domain => <<"x.internal">>})),
    %% Several blocked targets are still ONE double-weight signal.
    ?assertEqual(2, bifrost_api_handler:signal_weight(
                      [<<"cname_to_blocked:a.net">>, <<"cname_to_blocked:b.net">>])).

established_registration_discounts_test() ->
    ?assertEqual(-3, bifrost_api_handler:score_rdap(#{age_days => 10873})),
    ?assertEqual([<<"rdap:established">>], bifrost_api_handler:rdap_reasons(#{age_days => 10873})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{age_days => 729})),
    ?assertEqual(0, bifrost_api_handler:score_rdap(#{age_days => undefined})),
    ?assertEqual([], bifrost_api_handler:rdap_reasons(#{age_days => undefined})).

%% ── context helpers ──────────────────────────────────────────

suffixes_walk_label_boundaries_test() ->
    ?assertEqual([<<"a.b.example.com">>, <<"b.example.com">>, <<"example.com">>, <<"com">>],
                 bifrost_threat_context:suffixes(<<"a.b.example.com">>)),
    ?assertEqual(<<"gifteddonut.com">>, bifrost_threat_context:parent(<<"3.gifteddonut.com">>)),
    ?assertEqual(none, bifrost_threat_context:parent(<<"gifteddonut.com">>)).

match_list_honours_same_list_exceptions_test() ->
    SufMap = lists:foldl(fun({S, T}, M) -> maps:update_with(S, fun(L) -> [T | L] end, [T], M) end,
                         #{}, [{S, T} || T <- [<<"x.ads.com">>, <<"safe.ads.com">>],
                                         S <- bifrost_threat_context:suffixes(T)]),
    ?assertEqual(#{<<"x.ads.com">> => true},
                 bifrost_threat_context:match_list([<<"ads.com">>, <<"@@safe.ads.com">>,
                                                    <<"unrelated.org">>], SufMap)),
    ?assertEqual(#{}, bifrost_threat_context:match_list([<<"notads.com">>], SufMap)).

widespread_threshold_has_a_floor_test() ->
    ?assertEqual(5, bifrost_threat_context:widespread_threshold(0)),
    ?assertEqual(5, bifrost_threat_context:widespread_threshold(12)),
    ?assertEqual(16, bifrost_threat_context:widespread_threshold(64)),
    W = bifrost_threat_context:combine(#{clients => 16, widespread_threshold => 16}),
    ?assertMatch(#{score := -2, reasons := [<<"widespread">>]}, W),
    ?assertMatch(#{score := 0, reasons := []},
                 bifrost_threat_context:combine(#{clients => 15, widespread_threshold => 16})),
    ?assertMatch(#{score := 0, reasons := [<<"single_client">>]},
                 bifrost_threat_context:combine(#{clients => 1, widespread_threshold => 5})).

newly_seen_needs_history_test() ->
    ?assertNot(bifrost_threat_context:history_sufficient(undefined)),
    ?assertNot(bifrost_threat_context:history_sufficient(null)),
    ?assertNot(bifrost_threat_context:history_sufficient(29)),
    ?assert(bifrost_threat_context:history_sufficient(30)),
    ?assertMatch(#{score := 3, reasons := [<<"blocked_sibling">>, <<"newly_seen">>]},
                 bifrost_threat_context:combine(#{clients => 2, widespread_threshold => 5,
                                                  blocked_sibling => true, newly_seen => true})).

%% ── campaigns ────────────────────────────────────────────────

cand(D) -> cand(D, 2).
cand(D, H) -> #{domain => D, score => 4, hits => H}.

classify_requires_an_enumerated_label_test() ->
    ?assertEqual({enumerated, <<"lindseyblog.site">>, <<"447">>, <<"site">>, <<"lindseyblog.site">>},
                 bifrost_threat_campaigns:classify(<<"447.LindseyBlog.site">>)),
    ?assertMatch({enumerated, <<"alyssablog.site">>, <<"1xx">>, _, _},
                 bifrost_threat_campaigns:classify(<<"1xx.alyssablog.site">>)),
    [?assertEqual(none, bifrost_threat_campaigns:classify(D))
     || D <- [<<"api.firwinds.site">>, <<"447.site">>, <<"x1.blog.site">>,
              <<"447.this-url-does-not-exist.invalid">>]].

numbered_siblings_form_one_family_test() ->
    [Family] = bifrost_threat_campaigns:group(
                 [cand(<<(integer_to_binary(N))/binary, ".stg.content-loader.com">>)
                  || N <- lists:seq(0, 4)]),
    ?assertMatch(#{kind := family, parent := <<"stg.content-loader.com">>,
                   pattern := <<"{n}.stg.content-loader.com">>, tld := <<"com">>,
                   domain_count := 5, queries := 10}, Family).

one_operators_shards_are_not_a_marker_campaign_test() ->
    ?assertEqual([], bifrost_threat_campaigns:group(
                       [cand(<<"1.pool.ntp.org">>), cand(<<"1.cn.pool.ntp.org">>),
                        cand(<<"1.datadog.pool.ntp.org">>)])).

families_do_not_lend_members_to_markers_test() ->
    Donut = [cand(<<(integer_to_binary(N))/binary, ".gifteddonut.com">>) || N <- lists:seq(0, 3)],
    Loader = [cand(<<(integer_to_binary(N))/binary, ".stg.content-loader.com">>) || N <- lists:seq(0, 3)],
    Campaigns = bifrost_threat_campaigns:group([cand(<<"0.gravatar.com">>) | Donut ++ Loader]),
    ?assertEqual([<<"{n}.gifteddonut.com">>, <<"{n}.stg.content-loader.com">>],
                 lists:sort([maps:get(pattern, C) || C <- Campaigns])),
    ?assertNot(lists:member(<<"0.*.com">>, [maps:get(pattern, C) || C <- Campaigns])).

marker_spans_distinct_registrable_domains_test() ->
    [Campaign] = bifrost_threat_campaigns:group([
        cand(<<"447.a.site">>, 6), cand(<<"447.b.site">>, 2), cand(<<"447.c.site">>, 4),
        cand(<<"1xx.a.site">>, 2), cand(<<"1xx.b.site">>, 2),
        cand(<<"api.a.site">>, 12)]),
    ?assertMatch(#{kind := marker, pattern := <<"447.*.site">>, leading_label := <<"447">>,
                   domain_count := 3, queries := 12,
                   domains := [<<"447.a.site">>, <<"447.c.site">>, <<"447.b.site">>]},
                 Campaign),
    %% Three names, but two registrations: not a marker campaign.
    ?assertEqual([], bifrost_threat_campaigns:group(
                       [cand(<<"447.x.a.site">>), cand(<<"447.y.a.site">>), cand(<<"447.b.site">>)])).

campaign_dismissal_is_validated_test() ->
    ?assertEqual({ok, #{kind => marker, parent => null, tld => <<"site">>,
                        leading_label => <<"447">>, client_ip => {10, 10, 10, 250}, days => 30}},
                 bifrost_threat_campaigns:validate_dismissal(
                     #{<<"tld">> => <<"SITE">>, <<"leading_label">> => <<"447">>,
                       <<"client_ip">> => <<"10.10.10.250">>})),
    ?assertMatch({ok, #{kind := marker, client_ip := null, days := 7}},
                 bifrost_threat_campaigns:validate_dismissal(
                     #{<<"kind">> => <<"marker">>, <<"tld">> => <<"site">>,
                       <<"leading_label">> => <<"1xx">>, <<"client_ip">> => null, <<"days">> => 7})),
    [?assertMatch({error, _}, bifrost_threat_campaigns:validate_dismissal(B))
     || B <- [#{<<"tld">> => <<"site">>, <<"leading_label">> => <<"api">>},
              #{<<"tld">> => <<"s'te">>, <<"leading_label">> => <<"447">>},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"days">> => 0},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"days">> => 366},
              #{<<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>, <<"client_ip">> => <<"nope">>},
              #{<<"tld">> => <<"site">>},
              #{<<"kind">> => <<"bogus">>, <<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>}]].

family_dismissal_is_validated_test() ->
    ?assertEqual({ok, #{kind => family, parent => <<"stg.content-loader.com">>, tld => <<"com">>,
                        leading_label => null, client_ip => null, days => 30}},
                 bifrost_threat_campaigns:validate_dismissal(
                     #{<<"kind">> => <<"family">>, <<"parent">> => <<"Stg.Content-Loader.COM.">>})),
    [?assertEqual({error, <<"invalid parent">>}, bifrost_threat_campaigns:validate_dismissal(B))
     || B <- [#{<<"kind">> => <<"family">>},
              #{<<"kind">> => <<"family">>, <<"parent">> => <<"com">>},
              #{<<"kind">> => <<"family">>, <<"parent">> => <<"10.in-addr.arpa">>},
              #{<<"kind">> => <<"family">>, <<"parent">> => <<"a b.com">>},
              #{<<"kind">> => <<"family">>, <<"parent">> => 42}]].

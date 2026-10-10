%% Domain normalization for every operator-entered or query-log-sourced domain.
%% Rules, blocks and allowlist rows must all be stored in ONE canonical form, or
%% a block and an allow for the same name can coexist (the unblock invariant).
-module(bifrost_domain_tests).
-include_lib("eunit/include/eunit.hrl").

n(D) -> bifrost_domain:normalize(D).

lowercases_and_strips_trailing_dot_test() ->
    ?assertEqual({ok, <<"ads.example.com">>}, n(<<"Ads.Example.COM.">>)).

accepts_adblock_and_hosts_syntax_test() ->
    ?assertEqual({ok, <<"ads.com">>}, n(<<"||ads.com^">>)),
    ?assertEqual({ok, <<"ads.com">>}, n(<<"0.0.0.0 ads.com">>)),
    ?assertEqual({ok, <<"ads.com">>}, n(<<"*.ads.com">>)),
    ?assertEqual({ok, <<"ads.com">>}, n(<<"  ads.com  ">>)).

single_label_names_are_allowed_for_rules_test() ->
    %% Rewrites commonly target LAN names like `nas.home`, but also bare `nas`.
    ?assertEqual({ok, <<"nas">>}, n(<<"NAS">>)).

rejects_non_domains_test() ->
    ?assertEqual(error, n(<<>>)),
    ?assertEqual(error, n(<<"has space.com">>)),
    ?assertEqual(error, n(<<"<script>.com">>)),
    ?assertEqual(error, n(<<"@@||ads.com^">>)),
    ?assertEqual(error, n(<<"||ads.com^$third-party">>)),
    ?assertEqual(error, n(not_a_binary)).

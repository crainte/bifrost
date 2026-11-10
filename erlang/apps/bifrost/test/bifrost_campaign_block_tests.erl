%% Pure checks for explicit campaign blocking: request validation against a fresh
%% campaign listing, and the honest cross-node enforcement state. The DNS match
%% itself is covered by Rust (campaign_blocks.rs) and, against the SQL matcher
%% with the SAME vectors, by bifrost_campaign_block_SUITE.
-module(bifrost_campaign_block_tests).
-include_lib("eunit/include/eunit.hrl").

cand(D) -> #{domain => D, score => 4, hits => 2}.

campaigns() ->
    bifrost_threat_campaigns:group(
      [cand(<<(integer_to_binary(N))/binary, ".stg.content-loader.com">>) || N <- lists:seq(0, 3)] ++
      [cand(<<"447.a.site">>), cand(<<"447.b.site">>), cand(<<"447.c.site">>)]).

family_body() ->
    #{<<"kind">> => <<"family">>, <<"parent">> => <<"stg.content-loader.com">>,
      <<"pattern">> => <<"{n}.stg.content-loader.com">>, <<"client_ip">> => null,
      <<"confirm">> => true}.

marker_body() ->
    #{<<"kind">> => <<"marker">>, <<"tld">> => <<"site">>, <<"leading_label">> => <<"447">>,
      <<"pattern">> => <<"447.*.site">>, <<"client_ip">> => null, <<"confirm">> => true}.

%% ── validate_block/2 ──────────────────────────────────────────

confirmed_family_is_accepted_test() ->
    ?assertMatch({ok, #{kind := family, parent := <<"stg.content-loader.com">>, tld := <<"com">>,
                        leading_label := null, client_ip := null, observed_domains := 4}},
                 bifrost_threat_campaigns:validate_block(family_body(), campaigns())).

confirmed_marker_is_accepted_test() ->
    ?assertMatch({ok, #{kind := marker, tld := <<"site">>, leading_label := <<"447">>,
                        parent := null, client_ip := null, observed_domains := 3}},
                 bifrost_threat_campaigns:validate_block(marker_body(), campaigns())).

client_scope_is_taken_from_the_request_test() ->
    Body = (family_body())#{<<"client_ip">> => <<"192.168.1.42">>},
    ?assertMatch({ok, #{client_ip := {192, 168, 1, 42}}},
                 bifrost_threat_campaigns:validate_block(Body, campaigns())),
    ?assertEqual({error, <<"invalid client_ip">>},
                 bifrost_threat_campaigns:validate_block(
                   (family_body())#{<<"client_ip">> => <<"not-an-ip">>}, campaigns())).

omitted_or_blank_scope_must_not_become_an_all_client_block_test() ->
    [?assertEqual({error, <<"invalid client_ip">>},
                  bifrost_threat_campaigns:validate_block(Body, campaigns()))
     || Body <- [maps:remove(<<"client_ip">>, family_body()),
                 (family_body())#{<<"client_ip">> => <<>>}]],
    ?assertMatch({ok, #{client_ip := null}},
                 bifrost_threat_campaigns:validate_block(
                   (family_body())#{<<"client_ip">> => null}, campaigns())).

block_requires_explicit_confirmation_test() ->
    [?assertEqual({error, <<"confirmation required">>},
                  bifrost_threat_campaigns:validate_block(B, campaigns()))
     || B <- [maps:remove(<<"confirm">>, family_body()),
              (family_body())#{<<"confirm">> => false},
              (family_body())#{<<"confirm">> => <<"true">>},
              (marker_body())#{<<"confirm">> => 1}]].

stale_or_unknown_campaign_is_rejected_test() ->
    %% Pattern shape is valid but no such campaign is currently in the queue.
    ?assertEqual({error, <<"campaign is no longer available to block">>},
                 bifrost_threat_campaigns:validate_block(family_body(), [])),
    Other = (family_body())#{<<"parent">> => <<"stg.other.com">>,
                             <<"pattern">> => <<"{n}.stg.other.com">>},
    ?assertEqual({error, <<"campaign is no longer available to block">>},
                 bifrost_threat_campaigns:validate_block(Other, campaigns())),
    Label = (marker_body())#{<<"leading_label">> => <<"448">>,
                             <<"pattern">> => <<"448.*.site">>},
    ?assertEqual({error, <<"campaign is no longer available to block">>},
                 bifrost_threat_campaigns:validate_block(Label, campaigns())).

pattern_text_must_match_the_campaign_shown_test() ->
    %% The operator confirmed one pattern; the tuple names another shape.
    Wrong = (marker_body())#{<<"pattern">> => <<"447.*.com">>},
    ?assertEqual({error, <<"pattern does not match the campaign">>},
                 bifrost_threat_campaigns:validate_block(Wrong, campaigns())),
    Missing = maps:remove(<<"pattern">>, family_body()),
    ?assertEqual({error, <<"pattern does not match the campaign">>},
                 bifrost_threat_campaigns:validate_block(Missing, campaigns())).

invalid_shapes_are_rejected_test() ->
    [?assertMatch({error, _}, bifrost_threat_campaigns:validate_block(B, campaigns()))
     || B <- [#{<<"confirm">> => true, <<"kind">> => <<"regex">>, <<"pattern">> => <<".*">>},
              #{<<"confirm">> => true, <<"kind">> => <<"family">>, <<"parent">> => <<"com">>},
              #{<<"confirm">> => true, <<"kind">> => <<"marker">>, <<"tld">> => <<"site">>,
                <<"leading_label">> => <<"abc">>},
              #{<<"confirm">> => true, <<"kind">> => <<"marker">>, <<"tld">> => <<"a.site">>,
                <<"leading_label">> => <<"447">>},
              #{<<"confirm">> => true}]],
    ?assertEqual({error, <<"invalid body">>},
                 bifrost_threat_campaigns:validate_block(not_a_map, campaigns())).

parent_is_normalised_before_matching_test() ->
    Body = (family_body())#{<<"parent">> => <<"STG.Content-Loader.com.">>},
    ?assertMatch({ok, #{parent := <<"stg.content-loader.com">>}},
                 bifrost_threat_campaigns:validate_block(Body, campaigns())).

submitted_tuple_must_match_campaign_test() ->
    ?assertMatch({error, _}, bifrost_threat_campaigns:validate_block(
        (family_body())#{<<"tld">> => <<"net">>}, campaigns())),
    ?assertMatch({error, _}, bifrost_threat_campaigns:validate_block(
        (family_body())#{<<"leading_label">> => <<"447">>}, campaigns())),
    ?assertMatch({error, _}, bifrost_threat_campaigns:validate_block(
        (marker_body())#{<<"parent">> => <<"evil.site">>}, campaigns())).

connected_unacknowledged_resolver_blocks_admission_test() ->
    ?assertEqual({error, resolver_not_ready}, bifrost_campaign_policy:admission_status(
        [#{connected => true, applied_revision => undefined, state => <<"applying">>}])),
    ?assertEqual(ok, bifrost_campaign_policy:admission_status(
        [#{connected => false, applied_revision => undefined, state => <<"pending">>}])),
    ?assertEqual({error, resolver_not_ready}, bifrost_campaign_policy:admission_status(
        [#{state => <<"offline">>}])),
    ?assertEqual(ok, bifrost_campaign_policy:admission_status(
        [#{connected => true, applied_revision => 0, state => <<"applied">>}])).

%% ── rule_state/2: never claim enforcement the nodes have not confirmed ──

applied_node(R) -> #{applied_revision => R, state => <<"applied">>}.

rule_is_applied_only_when_every_node_has_applied_its_revision_test() ->
    ?assertEqual(applied, bifrost_campaign_policy:rule_state(5, [applied_node(5), applied_node(9)])),
    ?assertEqual(applying, bifrost_campaign_policy:rule_state(5, [applied_node(5), applied_node(4)])).

no_node_status_is_never_applied_test() ->
    ?assertEqual(applying, bifrost_campaign_policy:rule_state(5, [])).

an_unreachable_node_keeps_the_rule_applying_test() ->
    ?assertEqual(applying,
                 bifrost_campaign_policy:rule_state(5, [applied_node(5),
                                                         #{node => n2, state => <<"offline">>}])).

a_node_that_never_applied_keeps_the_rule_applying_test() ->
    %% An older Rust that does not know the message never acknowledges.
    ?assertEqual(applying,
                 bifrost_campaign_policy:rule_state(5, [applied_node(5),
                     #{desired_revision => 5, applied_revision => undefined,
                       state => <<"applying">>}])).

a_failing_node_that_is_behind_marks_the_rule_failed_test() ->
    ?assertEqual(failed,
                 bifrost_campaign_policy:rule_state(5, [applied_node(5),
                     #{desired_revision => 5, applied_revision => 4, state => <<"failed">>,
                       last_error => <<"ack_timeout">>}])).

stale_rust_ack_is_not_current_enforcement_test() ->
    Applied = #{revision => 5, connection_id => old_connection},
    ?assertEqual(5, bifrost_campaign_policy:effective_revision(Applied, old_connection)),
    ?assertEqual(undefined, bifrost_campaign_policy:effective_revision(Applied, new_connection)),
    ?assertEqual(undefined, bifrost_campaign_policy:effective_revision(Applied, undefined)),
    ?assertEqual(undefined, bifrost_campaign_policy:effective_revision(undefined, old_connection)).

disconnected_previously_serving_node_blocks_admission_test() ->
    ?assertEqual({error, resolver_not_ready},
                 bifrost_campaign_policy:admission_status(
                   [#{state => <<"pending">>, connected => false, had_ack => true}])),
    ?assertEqual(ok, bifrost_campaign_policy:admission_status(
                       [#{state => <<"pending">>, connected => false, had_ack => false}])).

%% Blocklist parsing. DNS can only block whole names, so the rule follows
%% AdGuard's DNS filtering syntax: a rule carrying any modifier the DNS layer
%% cannot honour ($third-party, $script, $domain=...) is IGNORED, never widened
%% to a whole-domain block. Otherwise browser lists (EasyList, EasyPrivacy)
%% over-block. https://adguard-dns.io/kb/general/dns-filtering-syntax/
-module(bifrost_blocklist_parser_tests).
-include_lib("eunit/include/eunit.hrl").

parse(Lines) ->
    bifrost_blocklist_manager:parse_blocklist(iolist_to_binary(lists:join("\n", Lines))).

hosts_format_test() ->
    ?assertEqual([<<"a.com">>, <<"b.com">>, <<"c.com">>, <<"d.com">>],
                 parse(["0.0.0.0 a.com", "127.0.0.1\tb.com", "0.0.0.0 c.com d.com"])).

hosts_inline_comment_and_case_test() ->
    ?assertEqual([<<"ads.example.com">>], parse(["0.0.0.0 Ads.Example.COM # tracker"])).

hosts_ipv6_and_local_entries_test() ->
    %% localhost-style entries and bare IPs are not blockable domains.
    ?assertEqual([<<"ads.com">>],
                 parse([":: ads.com", "::1 localhost", "0.0.0.0 0.0.0.0",
                        "127.0.0.1 localhost.localdomain", "255.255.255.255 broadcasthost"])).

plain_domains_test() ->
    ?assertEqual([<<"ads.com">>, <<"tracker.net">>], parse(["ads.com", "*.Tracker.net"])).

comments_and_cosmetic_rules_are_skipped_test() ->
    ?assertEqual([], parse(["# hosts comment", "! adblock comment", "[Adblock Plus 2.0]",
                            "example.com##.ad-banner", "example.com#@#.ad", "/ads[0-9]+/",
                            "", "   "])).

anchored_rules_test() ->
    ?assertEqual([<<"a.com">>, <<"b.com">>], parse(["||a.com^", "||B.com"])).

important_modifier_is_honoured_test() ->
    ?assertEqual([<<"a.com">>], parse(["||a.com^$important"])).

unsupported_modifiers_drop_the_whole_rule_test() ->
    ?assertEqual([], parse(["||a.com^$third-party", "||b.com^$script", "||c.com^$image,important",
                            "||d.com^$domain=example.org", "||e.com^$popup", "||f.com^$3p"])).

url_level_rules_are_skipped_test() ->
    ?assertEqual([], parse(["||a.com/ads/*", "||b.com^*banner", "||ads*.c.com^", "|https://d.com^"])).

mid_label_wildcards_are_not_domains_test() ->
    ?assertEqual([], parse(["ad*s.com", "0.0.0.0 tr*ck.net"])).

exceptions_become_list_local_allow_entries_test() ->
    ?assertEqual([<<"@@safe.ads.com">>, <<"ads.com">>], parse(["||ads.com^", "@@||safe.ads.com^"])).

exceptions_with_unsupported_modifiers_are_ignored_test() ->
    %% $document etc. are browser-page exceptions, not "never block this name".
    ?assertEqual([<<"ads.com">>], parse(["||ads.com^", "@@||ads.com^$document",
                                         "@@||ads.com^$elemhide"])).

badfilter_disables_the_matching_rule_test() ->
    ?assertEqual([<<"keep.com">>], parse(["||drop.com^", "||keep.com^", "||drop.com^$badfilter"])).

duplicates_are_collapsed_test() ->
    ?assertEqual([<<"a.com">>], parse(["a.com", "||a.com^", "0.0.0.0 A.com"])).

crlf_line_endings_test() ->
    ?assertEqual([<<"a.com">>, <<"b.com">>],
                 bifrost_blocklist_manager:parse_blocklist(<<"a.com\r\n||b.com^\r\n">>)).

%% parse_line/1 classifies; user-entered domains accept only plain blocks.
classify_test() ->
    ?assertEqual({block, <<"a.com">>}, bifrost_blocklist_manager:parse_line(<<"||A.com^">>)),
    ?assertEqual({except, <<"a.com">>}, bifrost_blocklist_manager:parse_line(<<"@@||a.com^">>)),
    ?assertEqual({badfilter, <<"a.com">>}, bifrost_blocklist_manager:parse_line(<<"||a.com^$badfilter">>)),
    ?assertEqual(skip, bifrost_blocklist_manager:parse_line(<<"||a.com^$third-party">>)),
    ?assertEqual(skip, bifrost_blocklist_manager:parse_line(<<"# comment">>)).

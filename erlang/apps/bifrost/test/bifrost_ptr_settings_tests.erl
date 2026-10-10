-module(bifrost_ptr_settings_tests).
-include_lib("eunit/include/eunit.hrl").

ipv6_reverse_name_test() ->
    ?assertEqual("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
                 bifrost_ptr:reverse_name("::1")),
    ?assertEqual("4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                 bifrost_ptr:reverse_name(<<"2001:db8::1234">>)).

resolver_settings_test() ->
    persistent_term:put({bifrost_dns_settings_server, effective}, #{
        settings => #{<<"reverse_dns">> => #{
            <<"enrichment_enabled">> => true,
            <<"resolvers">> => [#{<<"address">> => <<"fd00::53">>, <<"port">> => 5353}],
            <<"positive_ttl_seconds">> => 60, <<"negative_ttl_seconds">> => 5}},
        fingerprint => <<"one">>}),
    try
        ?assertEqual({ok, {{16#fd00, 0, 0, 0, 0, 0, 0, 16#53}, 5353}}, bifrost_ptr:resolver()),
        ?assertEqual({60, 5}, bifrost_ptr:ttl_seconds())
    after
        persistent_term:erase({bifrost_dns_settings_server, effective})
    end.

disabled_enrichment_test() ->
    persistent_term:put({bifrost_dns_settings_server, effective}, #{
        settings => #{<<"reverse_dns">> => #{
            <<"enrichment_enabled">> => false,
            <<"resolvers">> => [#{<<"address">> => <<"192.0.2.1">>, <<"port">> => 53}],
            <<"positive_ttl_seconds">> => 60, <<"negative_ttl_seconds">> => 5}},
        fingerprint => <<"two">>}),
    try
        ?assertEqual(undefined, bifrost_ptr:resolver()),
        ?assertEqual(<<"manual">>, bifrost_ptr:name_for(<<"10.0.0.1">>, <<"manual">>))
    after
        persistent_term:erase({bifrost_dns_settings_server, effective})
    end.

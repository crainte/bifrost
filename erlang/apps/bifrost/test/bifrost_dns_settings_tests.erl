-module(bifrost_dns_settings_tests).
-include_lib("eunit/include/eunit.hrl").

valid_settings_test() ->
    ?assertMatch({ok, _}, bifrost_dns_settings:validate(valid())).

suffix_normalization_test() ->
    Route = (group())#{<<"id">> => <<"lan">>, <<"domains">> => [<<"Corp.Internal.">>]},
    {ok, #{<<"routes">> := [Normalized]}} = bifrost_dns_settings:validate(
        (valid())#{<<"routes">> => [Route]}),
    ?assertEqual([<<"corp.internal">>], maps:get(<<"domains">>, Normalized)).

duplicate_suffixes_rejected_test() ->
    A = (group())#{<<"id">> => <<"a">>, <<"domains">> => [<<"Internal.">>]},
    B = (group())#{<<"id">> => <<"b">>, <<"domains">> => [<<"internal">>]},
    ?assertMatch({error, _}, bifrost_dns_settings:validate((valid())#{<<"routes">> => [A, B]})).

invalid_endpoints_test() ->
    lists:foreach(fun(Address) ->
        G = (group())#{<<"primary">> => [#{<<"address">> => Address, <<"port">> => 53}]},
        ?assertMatch({error, _}, bifrost_dns_settings:validate((valid())#{<<"upstreams">> => G}))
    end, [<<"resolver.example">>, <<"0.0.0.0">>, <<"::">>, <<"224.0.0.1">>, <<"ff02::1">>]).

invalid_limits_test() ->
    lists:foreach(fun(Change) ->
        ?assertMatch({error, _}, bifrost_dns_settings:validate(
            (valid())#{<<"upstreams">> => maps:merge(group(), Change)}))
    end, [#{<<"primary">> => []}, #{<<"timeout_ms">> => 0},
          #{<<"deadline_ms">> => 1000}, #{<<"strategy">> => <<"fastest_ip">>},
          #{<<"unknown">> => true}]).

unknown_sections_rejected_test() ->
    ?assertMatch({error, _}, bifrost_dns_settings:validate((valid())#{<<"password">> => <<"x">>})).

invalid_cache_and_blocking_test() ->
    ?assertMatch({error, _}, bifrost_dns_settings:validate(
        (valid())#{<<"cache">> => #{<<"min_ttl">> => 600, <<"max_ttl">> => 60,
                                    <<"max_entries">> => 1000}})),
    ?assertMatch({error, _}, bifrost_dns_settings:validate(
        (valid())#{<<"blocking">> => #{<<"mode">> => <<"custom_ip">>, <<"custom_ip">> => <<"bad">>}})).

no_implicit_public_upstreams_test() ->
    ?assertMatch({error, _}, bifrost_dns_settings:defaults(#{})).

legacy_defaults_preserved_test() ->
    {ok, D} = bifrost_dns_settings:defaults(#{
        upstreams => [[{address, "10.43.230.142"}, {port, 53}]],
        cache => [{max_ttl, 3600}, {min_ttl, 60}, {max_entries, 100000}],
        blocking => [{mode, zero_ip}, {custom_ip, ""}],
        ptr_resolver => "192.0.2.1"}),
    ?assertEqual(60, maps:get(<<"min_ttl">>, maps:get(<<"cache">>, D))),
    ?assertEqual(true, maps:get(<<"enrichment_enabled">>, maps:get(<<"reverse_dns">>, D))),
    ?assertEqual([], maps:get(<<"fallback">>, maps:get(<<"upstreams">>, D))).

valid() ->
    #{<<"schema_version">> => 1, <<"upstreams">> => group(), <<"routes">> => [],
      <<"cache">> => #{<<"min_ttl">> => 0, <<"max_ttl">> => 3600, <<"max_entries">> => 100000},
      <<"blocking">> => #{<<"mode">> => <<"zero_ip">>, <<"custom_ip">> => <<>>},
      <<"reverse_dns">> => #{<<"enrichment_enabled">> => false,
          <<"route_private_ptr">> => false, <<"resolvers">> => [],
          <<"positive_ttl_seconds">> => 21600, <<"negative_ttl_seconds">> => 300},
      <<"retention_months">> => 6}.

group() ->
    #{<<"primary">> => [#{<<"address">> => <<"192.0.2.1">>, <<"port">> => 53}],
      <<"fallback">> => [], <<"strategy">> => <<"sequential">>,
      <<"timeout_ms">> => 2000, <<"deadline_ms">> => 6000}.

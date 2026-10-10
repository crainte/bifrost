%% EUnit tests for bifrost_ptr pure logic: reverse-DNS name construction. These
%% exercise the actual PTR query-name building that a wrong implementation would
%% break (byte order, input types), not incidental plumbing.
-module(bifrost_ptr_tests).
-include_lib("eunit/include/eunit.hrl").

%% An IPv4 tuple reverses octets and appends the in-addr.arpa suffix.
reverse_name_tuple_test() ->
    ?assertEqual("42.0.10.10.in-addr.arpa",
                 bifrost_ptr:reverse_name({10, 10, 0, 42})).

%% A string IP produces the same reversed name (parsed then reversed).
reverse_name_string_test() ->
    ?assertEqual("5.1.168.192.in-addr.arpa",
                 bifrost_ptr:reverse_name("192.168.1.5")).

%% A binary IP is accepted and reversed identically.
reverse_name_binary_test() ->
    ?assertEqual("1.1.1.1.in-addr.arpa",
                 bifrost_ptr:reverse_name(<<"1.1.1.1">>)).

%% Octet order matters: the LAST octet leads the reversed name. A byte-order bug
%% would swap these, so assert both a value and its reverse are distinct+correct.
reverse_name_octet_order_test() ->
    ?assertEqual("1.2.3.4.in-addr.arpa", bifrost_ptr:reverse_name({4, 3, 2, 1})),
    ?assertEqual("4.3.2.1.in-addr.arpa", bifrost_ptr:reverse_name({1, 2, 3, 4})).

%% Boundary octets (0 and 255) are preserved, not clamped or dropped.
reverse_name_boundary_octets_test() ->
    ?assertEqual("255.0.255.0.in-addr.arpa",
                 bifrost_ptr:reverse_name({0, 255, 0, 255})).

%% A malformed string IP yields the error atom rather than crashing the caller.
reverse_name_invalid_string_test() ->
    ?assertEqual(error, bifrost_ptr:reverse_name("not.an.ip")).

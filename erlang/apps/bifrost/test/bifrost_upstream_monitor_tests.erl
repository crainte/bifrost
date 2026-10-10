-module(bifrost_upstream_monitor_tests).
-include_lib("eunit/include/eunit.hrl").

validates_response_id_question_and_rcode_test() ->
    {ok, Server} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Server),
    Self = self(),
    Pid = spawn(fun() -> responder(Server, Self) end),
    try
        ?assertEqual(ok, bifrost_upstream_monitor:probe(<<"127.0.0.1">>, Port, "internal", 500)),
        ?assertMatch({error, _}, bifrost_upstream_monitor:probe(<<"127.0.0.1">>, Port, "internal", 500)),
        ?assertMatch({error, _}, bifrost_upstream_monitor:probe(<<"127.0.0.1">>, Port, "internal", 500))
    after
        exit(Pid, kill),
        gen_udp:close(Server)
    end.

responder(Server, Parent) ->
    {ok, {Addr, Port, Q1}} = gen_udp:recv(Server, 512),
    ok = gen_udp:send(Server, Addr, Port, response(Q1, 3)),
    {ok, {Addr2, Port2, Q2}} = gen_udp:recv(Server, 512),
    <<Id:16, Rest/binary>> = response(Q2, 0),
    ok = gen_udp:send(Server, Addr2, Port2, <<(Id bxor 1):16, Rest/binary>>),
    {ok, {Addr3, Port3, Q3}} = gen_udp:recv(Server, 512),
    ok = gen_udp:send(Server, Addr3, Port3, response(Q3, 2)),
    Parent ! done.

response(Query, Rcode) ->
    {ok, Msg} = inet_dns:decode(Query),
    Header = inet_dns:msg(Msg, header),
    inet_dns:encode(inet_dns:make_msg(Msg, [{header, inet_dns:make_header(Header,
        [{qr, true}, {rcode, Rcode}])}])).

-module(bifrost_ptr_inflight_tests).
-include_lib("eunit/include/eunit.hrl").

-define(TABLE, bifrost_ptr_inflight).
-define(KEY, {bifrost_dns_settings_server, effective}).

inflight_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun table_survives_short_lived_caller/1,
      fun cap_admits_exactly_32_and_drains_to_zero/1,
      fun missing_table_is_a_noop/1]}.

setup() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Responder = spawn(fun() -> responder(Sock, held, []) end),
    ok = gen_udp:controlling_process(Sock, Responder),
    persistent_term:put(?KEY, #{
        settings => #{<<"reverse_dns">> => #{
            <<"enrichment_enabled">> => true,
            <<"resolvers">> => [#{<<"address">> => <<"127.0.0.1">>, <<"port">> => Port}],
            <<"positive_ttl_seconds">> => 60, <<"negative_ttl_seconds">> => 5}},
        fingerprint => <<"inflight">>}),
    Responder.

cleanup(Responder) ->
    stop_warmer(),
    exit(Responder, kill),
    persistent_term:erase(?KEY).

%% The table must belong to the long-lived warmer, not to whichever process
%% asked first: a Cowboy request process exiting used to delete it under its
%% own workers, which then crashed with badarg in their cleanup.
table_survives_short_lived_caller(Responder) ->
    fun() ->
        start_warmer(),
        Caller = spawn(fun() ->
            [bifrost_ptr:resolve_async(ip(N)) || N <- lists:seq(1, 5)]
        end),
        wait_dead(Caller),
        Responder ! release,
        ?assertEqual(ok, wait_drained()),
        ?assertNotEqual(undefined, ets:whereis(?TABLE))
    end.

%% Exactly 32 lookups may be in flight; the 32nd admission must not leak a
%% slot, or the counter sticks at the cap once the gateway is slow.
cap_admits_exactly_32_and_drains_to_zero(Responder) ->
    fun() ->
        start_warmer(),
        [bifrost_ptr:resolve_async(ip(N)) || N <- lists:seq(1, 40)],
        ?assertEqual(32, wait_queries(Responder, 32)),
        Responder ! release,
        ?assertEqual(ok, wait_drained())
    end.

missing_table_is_a_noop(_Responder) ->
    fun() ->
        ?assertEqual(undefined, ets:whereis(?TABLE)),
        ?assertEqual(ok, bifrost_ptr:resolve_async(<<"10.0.0.1">>)),
        ?assertEqual(undefined, ets:whereis(?TABLE))
    end.

%% ── helpers ───────────────────────────────────────────────────

ip(N) -> list_to_binary("10.9.0." ++ integer_to_list(N)).

start_warmer() ->
    {ok, Pid} = gen_server:start({local, bifrost_ptr_warmer}, bifrost_ptr_warmer, [], []),
    Pid.

stop_warmer() ->
    case whereis(bifrost_ptr_warmer) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

wait_dead(Pid) ->
    Ref = monitor(process, Pid),
    receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> error(caller_stuck) end.

wait_drained() -> wait_drained(erlang:monotonic_time(millisecond) + 3000).
wait_drained(Deadline) ->
    State = try ets:lookup(?TABLE, active) catch error:badarg -> no_table end,
    case State of
        [{active, 0}] -> ok;
        _ ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> {not_drained, State};
                false -> timer:sleep(20), wait_drained(Deadline)
            end
    end.

%% Distinct reverse names the responder has seen; waits briefly past Want so
%% an over-admission would also be caught.
wait_queries(Responder, Want) ->
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    wait_queries(Responder, Want, Deadline).
wait_queries(Responder, Want, Deadline) ->
    Responder ! {count, self()},
    N = receive {count, C} -> C after 1000 -> 0 end,
    case N >= Want orelse erlang:monotonic_time(millisecond) > Deadline of
        true ->
            timer:sleep(200),
            Responder ! {count, self()},
            receive {count, Final} -> Final after 1000 -> N end;
        false -> timer:sleep(20), wait_queries(Responder, Want, Deadline)
    end.

%% Holds queries until `release`, then answers NXDOMAIN to everything.
responder(Sock, Mode, Held) ->
    receive
        release ->
            [reply(Sock, Q) || Q <- Held],
            responder(Sock, open, Held);
        {count, From} ->
            From ! {count, length(lists:usort([qname(P) || {_, _, P} <- Held]))},
            responder(Sock, Mode, Held)
    after 0 ->
        case gen_udp:recv(Sock, 512, 10) of
            {ok, Q} when Mode =:= open -> reply(Sock, Q), responder(Sock, Mode, Held);
            {ok, Q} -> responder(Sock, Mode, [Q | Held]);
            {error, timeout} -> responder(Sock, Mode, Held)
        end
    end.

reply(Sock, {Addr, Port, Query}) ->
    {ok, Msg} = inet_dns:decode(Query),
    Header = inet_dns:msg(Msg, header),
    Resp = inet_dns:encode(inet_dns:make_msg(Msg, [{header, inet_dns:make_header(Header,
        [{qr, true}, {rcode, 3}])}])),
    gen_udp:send(Sock, Addr, Port, Resp).

qname(Packet) ->
    {ok, Msg} = inet_dns:decode(Packet),
    inet_dns:dns_query(hd(inet_dns:msg(Msg, qdlist)), domain).

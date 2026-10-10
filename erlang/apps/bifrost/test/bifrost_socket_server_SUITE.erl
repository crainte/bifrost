%% bifrost_socket_server against a fake Rust client on a REAL Unix socket.
%% Pins the IPC contract: one bidirectional connection per Rust process, the
%% newest connection always wins, every connect triggers re-hydration, a client
%% that stops reading cannot wedge the server, and a bad inbound message cannot
%% crash it.
-module(bifrost_socket_server_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([control_messages_reach_the_connected_client/1,
         newest_connection_replaces_the_old_one/1,
         every_connect_triggers_hydration/1,
         events_are_routed_to_the_query_writer/1,
         bad_cache_store_does_not_crash_the_server/1,
         stalled_client_cannot_block_senders_forever/1]).

all() ->
    [control_messages_reach_the_connected_client,
     newest_connection_replaces_the_old_one,
     every_connect_triggers_hydration,
     events_are_routed_to_the_query_writer,
     bad_cache_store_does_not_crash_the_server,
     stalled_client_cannot_block_senders_forever].

init_per_testcase(_TC, Config) ->
    Path = "/tmp/bifrost_ipc_ct_" ++ integer_to_list(erlang:unique_integer([positive])),
    application:set_env(bifrost, ipc_send_timeout, 500),
    Self = self(),
    %% Stand-ins for the registered processes the server talks to.
    Manager = spawn_link(fun() -> forward_loop(Self, manager) end),
    register(bifrost_blocklist_manager, Manager),
    Writer = spawn_link(fun() -> forward_loop(Self, writer) end),
    register(bifrost_query_writer, Writer),
    {ok, Pid} = bifrost_socket_server:start_link(Path),
    unlink(Pid),
    [{path, Path}, {server, Pid} | Config].

end_per_testcase(_TC, Config) ->
    Pid = ?config(server, Config),
    catch exit(Pid, kill),
    catch unregister(bifrost_blocklist_manager),
    catch unregister(bifrost_query_writer),
    file:delete(?config(path, Config)),
    application:unset_env(bifrost, ipc_send_timeout),
    ok.

forward_loop(To, Tag) ->
    receive Msg -> To ! {Tag, Msg}, forward_loop(To, Tag) end.

connect(Config) ->
    {ok, S} = gen_tcp:connect({local, ?config(path, Config)}, 0,
                              [binary, {packet, 4}, {active, false}], 2000),
    S.

recv_json(S) ->
    {ok, Bin} = gen_tcp:recv(S, 0, 2000),
    jsx:decode(Bin, [return_maps]).

wait_hydrations(0) -> ok;
wait_hydrations(N) ->
    receive {manager, {'$gen_cast', client_connected}} -> wait_hydrations(N - 1)
    after 3000 -> ct:fail(no_hydration_trigger)
    end.

%% ── cases ─────────────────────────────────────────────────────

control_messages_reach_the_connected_client(Config) ->
    S = connect(Config),
    wait_hydrations(1),
    ok = bifrost_socket_server:send_message(#{type => <<"reload_complete">>}),
    ?assertEqual(#{<<"type">> => <<"reload_complete">>}, recv_json(S)).

%% A restarted Rust process connects again while the old socket may not have
%% been noticed as closed yet. Control traffic must go to the NEW process.
newest_connection_replaces_the_old_one(Config) ->
    Old = connect(Config),
    wait_hydrations(1),
    New = connect(Config),
    wait_hydrations(1),
    ok = bifrost_socket_server:send_message(#{type => <<"ping">>}),
    ?assertEqual(#{<<"type">> => <<"ping">>}, recv_json(New)),
    ?assertMatch({error, closed}, gen_tcp:recv(Old, 0, 1000)).

%% A reconnect means a Rust process with empty state; it must be re-hydrated
%% every time, not only on the first connect.
every_connect_triggers_hydration(Config) ->
    A = connect(Config),
    wait_hydrations(1),
    gen_tcp:close(A),
    _B = connect(Config),
    wait_hydrations(1).

events_are_routed_to_the_query_writer(Config) ->
    S = connect(Config),
    wait_hydrations(1),
    Event = #{<<"type">> => <<"query_event">>, <<"domain">> => <<"a.example">>},
    ok = gen_tcp:send(S, jsx:encode(Event)),
    receive {writer, {'$gen_cast', {query_event, #{<<"domain">> := <<"a.example">>}}}} -> ok
    after 2000 -> ct:fail(event_not_routed)
    end.

%% Mnesia is not running in this suite, so writing a cache entry raises. That
%% used to escape the try (it ran in the `of` body) and kill the server.
bad_cache_store_does_not_crash_the_server(Config) ->
    S = connect(Config),
    wait_hydrations(1),
    Store = #{<<"type">> => <<"cache_store">>, <<"domain">> => <<"x.example">>,
              <<"qtype">> => 1, <<"response">> => base64:encode(<<1,2,3>>), <<"ttl">> => 60},
    ok = gen_tcp:send(S, jsx:encode(Store)),
    ok = gen_tcp:send(S, <<"{not json">>),
    timer:sleep(200),
    ?assert(is_process_alive(?config(server, Config))),
    ok = bifrost_socket_server:send_message(#{type => <<"still_up">>}),
    ?assertEqual(#{<<"type">> => <<"still_up">>}, recv_json(S)).

%% A Rust process that stops reading (wedged, or a socket Rust no longer reads)
%% must make sends fail fast instead of blocking the caller forever.
stalled_client_cannot_block_senders_forever(Config) ->
    _S = connect(Config),
    wait_hydrations(1),
    Big = #{type => <<"load_blocklist">>, list_id => <<"l">>,
            entries => [<<"padding-domain-", (integer_to_binary(N))/binary, ".example">>
                        || N <- lists:seq(1, 20000)]},
    Parent = self(),
    spawn_link(fun() -> Parent ! {sent, send_until_error(Big, 200)} end),
    receive
        {sent, Result} -> ?assertMatch({error, _}, Result)
    after 10000 ->
        ct:fail(send_blocked_forever)
    end.

send_until_error(_Msg, 0) -> all_sent;
send_until_error(Msg, N) ->
    case bifrost_socket_server:send_message(Msg) of
        ok -> send_until_error(Msg, N - 1);
        Error -> Error
    end.

-module(bifrost_upstream_monitor).
-behaviour(gen_server).

-export([start_link/0, get_upstream/1, get_all/0, probe/4]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(TABLE, bifrost_upstream_status).
-define(CHECK_INTERVAL, 30000).
-define(PROBE_TIMEOUT, 2000).
-define(MAX_PROBES, 64).

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

get_upstream(Key) ->
    try ets:lookup(?TABLE, Key) of
        [{_, V}] -> V;
        [] -> undefined
    catch error:badarg -> undefined
    end.

get_all() ->
    try ets:tab2list(?TABLE)
    catch error:badarg -> []
    end.

-record(state, {timer, generation = 0}).

init([]) ->
    ets:new(?TABLE, [named_table, public, set, {read_concurrency, true}]),
    self() ! check,
    {ok, #state{}}.

handle_call(_Request, _From, State) -> {reply, ok, State}.
handle_cast(_Msg, State) -> {noreply, State}.

handle_info(check, State = #state{timer = Old, generation = G0}) ->
    cancel(Old),
    G = G0 + 1,
    Targets = lists:sublist(targets(), ?MAX_PROBES),
    Keys = [{A, P, Role} || {A, P, Role, _} <- Targets],
    [ets:delete(?TABLE, K) || {K, _} <- ets:tab2list(?TABLE), not lists:member(K, Keys)],
    Now = erlang:system_time(millisecond),
    [case ets:lookup(?TABLE, {A, P, Role}) of
         [] -> ets:insert(?TABLE, {{A, P, Role}, row(A, P, Role, <<"unknown">>, null, Now, G)});
         _ -> ok
     end || {A, P, Role, _} <- Targets],
    Parent = self(),
    [spawn(fun() -> Parent ! {checked, G, {A, P, Role}, timed_probe(A, P, Name)} end)
     || {A, P, Role, Name} <- Targets],
    {noreply, State#state{generation = G,
                          timer = erlang:send_after(?CHECK_INTERVAL, self(), check)}};
handle_info({checked, G, {A, P, Role} = Key, {Result, Latency}}, State = #state{generation = G}) ->
    Status = case Result of ok -> <<"up">>; _ -> <<"down">> end,
    ets:insert(?TABLE, {Key, row(A, P, Role, Status, Latency, erlang:system_time(millisecond), G)}),
    {noreply, State};
handle_info(_Info, State) -> {noreply, State}.

targets() ->
    case bifrost_dns_settings_server:effective() of
        {ok, #{settings := S}} ->
            Default = endpoints(maps:get(<<"upstreams">>, S), <<"default">>, "."),
            Routes = lists:append([endpoints(R, <<"route:", (maps:get(<<"id">>, R))/binary>>,
                                             binary_to_list(hd(maps:get(<<"domains">>, R))))
                                   || R <- maps:get(<<"routes">>, S)]),
            Reverse = [{maps:get(<<"address">>, E), maps:get(<<"port">>, E), <<"private_reverse">>,
                        "10.in-addr.arpa"}
                       || E <- maps:get(<<"resolvers">>, maps:get(<<"reverse_dns">>, S))],
            lists:usort(Default ++ Routes ++ Reverse);
        _ -> []
    end.

endpoints(Group, Role, Name) ->
    [{maps:get(<<"address">>, E), maps:get(<<"port">>, E), Role, Name}
     || E <- maps:get(<<"primary">>, Group) ++ maps:get(<<"fallback">>, Group)].

timed_probe(A, P, Name) ->
    T0 = erlang:monotonic_time(microsecond),
    Result = probe(A, P, Name, ?PROBE_TIMEOUT),
    {Result, case Result of
                 ok -> max(0, (erlang:monotonic_time(microsecond) - T0) div 1000);
                 _ -> null
             end}.

probe(Address, Port, Name, Timeout) ->
    case inet:parse_address(binary_to_list(Address)) of
        {ok, Ip} ->
            Family = case tuple_size(Ip) of 4 -> inet; 8 -> inet6 end,
            Id = rand:uniform(65535),
            Question = inet_dns:make_dns_query([{domain, Name}, {type, soa}, {class, in}]),
            Query = inet_dns:encode(inet_dns:make_msg([{header, inet_dns:make_header(
                [{id, Id}, {qr, false}, {opcode, query}, {rd, true}])}, {qdlist, [Question]}])),
            case gen_udp:open(0, [binary, Family, {active, false}]) of
                {ok, Sock} ->
                    try
                        ok = gen_udp:connect(Sock, Ip, Port),
                        ok = gen_udp:send(Sock, Query),
                        await(Sock, Id, Name, erlang:monotonic_time(millisecond) + Timeout)
                    catch _:R -> {error, R}
                    after gen_udp:close(Sock)
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

await(Sock, Id, Name, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 andalso gen_udp:recv(Sock, 4096, Remaining) of
        false -> {error, timeout};
        {ok, {_, _, Data}} ->
            case valid(Data, Id, Name) of
                ok -> ok;
                {error, servfail} -> {error, servfail};
                _ -> {error, invalid_response}
            end;
        {error, Reason} -> {error, Reason}
    end.

valid(Data, Id, Name) ->
    case inet_dns:decode(Data) of
        {ok, Msg} ->
            H = inet_dns:msg(Msg, header),
            Q = inet_dns:msg(Msg, qdlist),
            Rcode = inet_dns:header(H, rcode),
            Expected = string:trim(string:lowercase(Name), trailing, "."),
            Matches = inet_dns:header(H, id) =:= Id andalso inet_dns:header(H, qr) =:= true
                andalso length(Q) =:= 1
                andalso string:lowercase(string:trim(inet_dns:dns_query(hd(Q), domain), trailing, ".")) =:= Expected
                andalso inet_dns:dns_query(hd(Q), type) =:= soa,
            case {Matches, Rcode} of
                {true, R} when R =:= servfail; R =:= 2 -> {error, servfail};
                {true, R} when R =:= refused; R =:= 5 -> {error, refused};
                {true, _} -> ok;
                _ -> {error, mismatch}
            end;
        _ -> {error, malformed}
    end.

row(A, P, Role, Status, Latency, Now, G) ->
    #{address => A, port => P, role => Role, status => Status, latency_ms => Latency,
      last_checked => Now, generation => G,
      note => <<"Probe health only; resolver selection uses Rust's real-query latency.">>}.

cancel(undefined) -> ok;
cancel(Ref) -> erlang:cancel_timer(Ref).

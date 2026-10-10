-module(bifrost_dns_settings).
-export([validate/1, defaults/1]).

validate(Value) ->
    try
        keys(Value, [<<"schema_version">>, <<"upstreams">>, <<"routes">>, <<"cache">>,
                     <<"blocking">>, <<"reverse_dns">>, <<"retention_months">>]),
        true = maps:get(<<"schema_version">>, Value) =:= 1,
        Group = group(maps:get(<<"upstreams">>, Value)),
        Routes0 = maps:get(<<"routes">>, Value),
        true = is_list(Routes0) andalso length(Routes0) =< 256,
        Routes = [route(R) || R <- Routes0],
        unique([maps:get(<<"id">>, R) || R <- Routes]),
        unique(lists:append([maps:get(<<"domains">>, R) || R <- Routes])),
        Cache = maps:get(<<"cache">>, Value),
        keys(Cache, [<<"min_ttl">>, <<"max_ttl">>, <<"max_entries">>]),
        Min = integer(Cache, <<"min_ttl">>, 0, 86400),
        _ = integer(Cache, <<"max_ttl">>, Min, 604800),
        _ = integer(Cache, <<"max_entries">>, 0, 1000000),
        Blocking = maps:get(<<"blocking">>, Value),
        keys(Blocking, [<<"mode">>, <<"custom_ip">>]),
        Mode = maps:get(<<"mode">>, Blocking),
        true = lists:member(Mode, [<<"zero_ip">>, <<"nxdomain">>, <<"refused">>, <<"custom_ip">>]),
        Custom = maps:get(<<"custom_ip">>, Blocking),
        true = is_binary(Custom),
        case Mode of
            <<"custom_ip">> -> {ok, _} = inet:parse_address(binary_to_list(Custom));
            _ -> true = Custom =:= <<>>
        end,
        Reverse = maps:get(<<"reverse_dns">>, Value),
        keys(Reverse, [<<"enrichment_enabled">>, <<"route_private_ptr">>, <<"resolvers">>,
                       <<"positive_ttl_seconds">>, <<"negative_ttl_seconds">>]),
        Enrich = maps:get(<<"enrichment_enabled">>, Reverse),
        Routing = maps:get(<<"route_private_ptr">>, Reverse),
        true = is_boolean(Enrich) andalso is_boolean(Routing),
        Resolvers = endpoints(maps:get(<<"resolvers">>, Reverse)),
        true = not (Enrich orelse Routing) orelse Resolvers =/= [],
        _ = integer(Reverse, <<"positive_ttl_seconds">>, 1, 604800),
        _ = integer(Reverse, <<"negative_ttl_seconds">>, 1, 86400),
        _ = integer(Value, <<"retention_months">>, 0, 1200),
        {ok, Value#{<<"upstreams">> => Group, <<"routes">> => Routes,
                    <<"reverse_dns">> => Reverse#{<<"resolvers">> => Resolvers}}}
    catch
        throw:{invalid, Field} -> {error, Field};
        error:{badkey, Key} -> {error, Key};
        error:_ -> {error, <<"invalid_settings">>}
    end.

keys(Map, Allowed) when is_map(Map) ->
    case lists:sort(maps:keys(Map)) =:= lists:sort(Allowed) of
        true -> ok;
        false -> throw({invalid, <<"fields">>})
    end;
keys(_, _) -> throw({invalid, <<"object_required">>}).

integer(Map, Key, Min, Max) ->
    V = maps:get(Key, Map),
    case is_integer(V) andalso V >= Min andalso V =< Max of
        true -> V;
        false -> throw({invalid, Key})
    end.

group(G) ->
    keys(G, [<<"primary">>, <<"fallback">>, <<"strategy">>, <<"timeout_ms">>, <<"deadline_ms">>]),
    Primary = endpoints(maps:get(<<"primary">>, G)),
    true = Primary =/= [],
    Fallback = endpoints(maps:get(<<"fallback">>, G)),
    unique(Primary ++ Fallback),
    true = lists:member(maps:get(<<"strategy">>, G), [<<"sequential">>, <<"parallel">>, <<"fastest">>]),
    Timeout = integer(G, <<"timeout_ms">>, 100, 10000),
    _ = integer(G, <<"deadline_ms">>, Timeout, 30000),
    G#{<<"primary">> => Primary, <<"fallback">> => Fallback}.

endpoints(Entries) when is_list(Entries), length(Entries) =< 8 ->
    Values = [endpoint(E) || E <- Entries],
    unique(Values),
    Values;
endpoints(_) -> throw({invalid, <<"endpoints">>}).

endpoint(E) ->
    keys(E, [<<"address">>, <<"port">>]),
    Address = maps:get(<<"address">>, E),
    true = is_binary(Address) andalso byte_size(Address) =< 45,
    {ok, IP} = inet:parse_address(binary_to_list(Address)),
    true = permitted_ip(IP),
    _ = integer(E, <<"port">>, 1, 65535),
    E#{<<"address">> => list_to_binary(inet:ntoa(IP))}.

permitted_ip({0, 0, 0, 0}) -> false;
permitted_ip({A, _, _, _}) when A >= 224 -> false;
permitted_ip({0, 0, 0, 0, 0, 0, 0, 0}) -> false;
permitted_ip({A, _, _, _, _, _, _, _}) when A band 16#ff00 =:= 16#ff00 -> false;
permitted_ip({0, 0, 0, 0, 0, 16#ffff, A, B}) ->
    permitted_ip({A bsr 8, A band 255, B bsr 8, B band 255});
permitted_ip(_) -> true.

route(R) ->
    Id = maps:get(<<"id">>, R),
    true = is_binary(Id) andalso byte_size(Id) > 0 andalso byte_size(Id) =< 64,
    {match, _} = re:run(Id, <<"^[a-zA-Z0-9_-]+$">>),
    G = group(maps:without([<<"id">>, <<"domains">>], R)),
    Domains = maps:get(<<"domains">>, R),
    true = is_list(Domains) andalso length(Domains) > 0 andalso length(Domains) =< 32,
    G#{<<"id">> => Id, <<"domains">> => [suffix(D) || D <- Domains]}.

suffix(D) when is_binary(D), byte_size(D) > 0, byte_size(D) =< 254 ->
    Lower = list_to_binary(string:lowercase(binary_to_list(D))),
    Normal = case binary:last(Lower) of
        $. -> binary:part(Lower, 0, byte_size(Lower) - 1);
        _ -> Lower
    end,
    true = byte_size(Normal) > 0 andalso byte_size(Normal) =< 253,
    lists:foreach(fun(Label) ->
        true = byte_size(Label) > 0 andalso byte_size(Label) =< 63,
        {match, _} = re:run(Label, <<"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$">>)
    end, binary:split(Normal, <<".">>, [global])),
    Normal;
suffix(_) -> throw({invalid, <<"domains">>}).

unique(Values) ->
    case length(Values) =:= length(lists:usort(Values)) of
        true -> ok;
        false -> throw({invalid, <<"duplicate">>})
    end.

defaults(Config) ->
    try
        Primary = [#{<<"address">> => text(proplists:get_value(address, E)),
                     <<"port">> => proplists:get_value(port, E, 53)}
                   || E <- maps:get(upstreams, Config, [])],
        Cache = maps:get(cache, Config, []),
        Blocking = maps:get(blocking, Config, []),
        Ptr = text(maps:get(ptr_resolver, Config, "")),
        Resolvers = case Ptr of
            <<>> -> [];
            _ -> [#{<<"address">> => Ptr, <<"port">> => 53}]
        end,
        validate(#{<<"schema_version">> => 1,
          <<"upstreams">> => #{<<"primary">> => Primary, <<"fallback">> => [],
              <<"strategy">> => <<"sequential">>, <<"timeout_ms">> => 2000,
              <<"deadline_ms">> => 6000},
          <<"routes">> => [],
          <<"cache">> => #{<<"min_ttl">> => proplists:get_value(min_ttl, Cache, 0),
              <<"max_ttl">> => proplists:get_value(max_ttl, Cache, 3600),
              <<"max_entries">> => proplists:get_value(max_entries, Cache, 100000)},
          <<"blocking">> => #{<<"mode">> => text(proplists:get_value(mode, Blocking, nxdomain)),
              <<"custom_ip">> => text(proplists:get_value(custom_ip, Blocking, ""))},
          <<"reverse_dns">> => #{<<"enrichment_enabled">> => Resolvers =/= [],
              <<"route_private_ptr">> => false, <<"resolvers">> => Resolvers,
              <<"positive_ttl_seconds">> => 21600, <<"negative_ttl_seconds">> => 300},
          <<"retention_months">> => 6})
    catch error:_ -> {error, <<"deployment_defaults">>} end.

text(V) when is_binary(V) -> V;
text(V) when is_list(V) -> list_to_binary(V);
text(V) when is_atom(V) -> atom_to_binary(V, utf8).

-module(bifrost_settings_handler).
-export([init/2, structural_summary/0]).

-define(MAX_BODY, 262144).
-define(JSON, #{<<"content-type">> => <<"application/json">>,
                <<"cache-control">> => <<"no-store">>}).

init(Req0, settings) ->
    Req = try handle(cowboy_req:method(Req0), Req0)
          catch C:R:S ->
              logger:error("settings handler failed: ~p:~p~n~p", [C, R, S]),
              reply(500, #{error => <<"internal_error">>}, Req0)
          end,
    {ok, Req, settings}.

handle(<<"GET">>, Req) ->
    _ = catch bifrost_dns_settings_server:refresh(),
    case bifrost_dns_settings_server:effective() of
        {ok, Effective} -> reply(200, view(Effective), Req);
        {error, _} -> reply(503, #{error => <<"settings_unavailable">>}, Req)
    end;
handle(<<"PUT">>, Req0) ->
    case cowboy_req:body_length(Req0) of
        Length when is_integer(Length), Length > ?MAX_BODY ->
            reply(413, #{error => <<"payload_too_large">>}, Req0);
        _ -> read_and_save(Req0)
    end;
handle(_, Req) ->
    reply(405, #{error => <<"method_not_allowed">>}, Req).

read_and_save(Req0) ->
    case cowboy_req:read_body(Req0, #{length => ?MAX_BODY + 1, period => 5000}) of
        {ok, Body, Req1} when byte_size(Body) =< ?MAX_BODY ->
            try jsx:decode(Body, [return_maps]) of
                #{<<"revision">> := Revision, <<"settings">> := Settings, <<"reset">> := Reset} = Request
                  when map_size(Request) =:= 3, is_integer(Revision), Revision >= 0,
                       is_map(Settings), is_list(Reset) ->
                    save(Revision, Settings, Reset, Req1);
                _ -> reply(400, #{error => <<"invalid_request">>}, Req1)
            catch _:_ -> reply(400, #{error => <<"invalid_json">>}, Req1)
            end;
        {_, _, Req1} -> reply(413, #{error => <<"payload_too_large">>}, Req1)
    end.

save(Revision, Settings, Reset, Req) ->
    case bifrost_dns_settings_server:save(Revision, Settings, Reset, node()) of
        {ok, Saved} -> reply(200, saved(Saved), Req);
        {saved_pending, Saved, Reason} ->
            reply(202, (saved(Saved))#{state => <<"saved_publish_pending">>,
                                       error => iolist_to_binary(io_lib:format("~p", [Reason]))}, Req);
        {error, conflict} -> reply(409, #{error => <<"conflict">>,
            message => <<"Settings changed in another session. Reload before saving.">>}, Req);
        {error, {invalid, Field}} -> reply(400, #{error => <<"invalid_settings">>,
                                                  field => printable(Field)}, Req);
        {error, {database, _}} -> reply(503, #{error => <<"database_unavailable">>,
            message => <<"Settings are read-only until PostgreSQL is reachable.">>}, Req);
        {error, _} -> reply(503, #{error => <<"settings_unavailable">>}, Req)
    end.

saved(Saved) ->
    #{revision => maps:get(revision, Saved), state => <<"pending">>,
      message => <<"Saved. Waiting for every DNS node to apply it.">>}.

view(Effective) ->
    #{revision => maps:get(revision, Effective),
      fingerprint => maps:get(fingerprint, Effective),
      settings => maps:get(settings, Effective),
      defaults => maps:get(defaults, Effective),
      sources => maps:get(sources, Effective),
      snapshot_source => atom_or_binary(maps:get(snapshot_source, Effective)),
      cluster => [status_view(S) || S <- bifrost_dns_settings_server:cluster_status()],
      structural => structural_summary(),
      safety => #{non_in_classes => <<"refused">>,
                  private_reverse => <<"never forwarded to default resolvers">>},
      retention_effect => <<"Retention is enforced during monthly partition maintenance; saving does not delete history immediately.">>}.

status_view(S) ->
    maps:map(fun(_, V) when is_atom(V), V =/= undefined, V =/= true, V =/= false -> atom_to_binary(V);
                (_, undefined) -> null;
                (_, V) -> V end, S).

structural_summary() ->
    Config = case catch bifrost_config_server:get_config() of {ok, C} -> C; _ -> #{} end,
    Network = maps:get(network, Config, []),
    Acl = [list_to_binary(A) || A <- proplists:get_value(allowed_clients, Network, []),
                                 is_list(A)],
    #{listen_address => text(proplists:get_value(listen_address, Network, "0.0.0.0")),
      listen_port => proplists:get_value(listen_port, Network, 53),
      allowed_clients => Acl,
      discovery => case {os:getenv("BIFROST_CLUSTER_NODES"), os:getenv("BIFROST_CLUSTER_SERVICE")} of
                       {N, _} when N =/= false, N =/= "" -> <<"explicit nodes">>;
                       {_, S} when S =/= false, S =/= "" -> <<"headless service">>;
                       _ -> <<"single node">>
                   end,
      config_source => <<"deployment configuration">>}.

reply(Code, Body, Req) -> cowboy_req:reply(Code, ?JSON, jsx:encode(Body), Req).
printable(V) when is_binary(V) -> V;
printable(V) -> iolist_to_binary(io_lib:format("~p", [V])).
atom_or_binary(V) when is_atom(V) -> atom_to_binary(V);
atom_or_binary(V) -> V.
text(V) when is_list(V) -> list_to_binary(V);
text(V) when is_binary(V) -> V;
text(V) -> printable(V).

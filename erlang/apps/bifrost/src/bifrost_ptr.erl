%% Reverse-DNS (PTR) client-name enrichment. Out-of-band, control-plane only —
%% never on the Rust hot path. RFC1918 PTR resolves only against the LAN
%% authority, so lookups target an operator-configured `ptr_resolver` (the
%% gateway), NOT the configured upstreams. If `ptr_resolver` is unset, PTR is
%% disabled entirely and callers fall back to label > IP.
-module(bifrost_ptr).

-export([reverse_name/1, resolver/0, cached_name/1, resolve_async/1, name_for/2, warm/0,
         ttl_seconds/0, visible_provenance/0]).

%% Default re-resolve age (PTR changes per DHCP lease). Overridable at runtime
%% via the settings table key `ptr_ttl_seconds` (see ttl_seconds/0).
-define(TTL_DEFAULT, 21600).  %% 6 hours

%% ── Reverse name construction ─────────────────────────────────
%% "192.168.1.42" -> "42.1.168.192.in-addr.arpa" (pure; unit-tested via selfcheck/0).
reverse_name({A, B, C, D}) ->
    lists:flatten(io_lib:format("~b.~b.~b.~b.in-addr.arpa", [D, C, B, A]));
reverse_name({_, _, _, _, _, _, _, _} = Ip) ->
    Hex = lists:flatten([io_lib:format("~4.16.0b", [P]) || P <- tuple_to_list(Ip)]),
    string:join([[C] || C <- lists:reverse(Hex)], ".") ++ ".ip6.arpa";
reverse_name(Ip) when is_list(Ip) ->
    case inet:parse_address(Ip) of
        {ok, {0, 0, 0, 0, 0, 16#ffff, A, B}} ->
            reverse_name({A bsr 8, A band 255, B bsr 8, B band 255});
        {ok, Tuple} -> reverse_name(Tuple);
        {error, _} -> error
    end;
reverse_name(Ip) when is_binary(Ip) ->
    reverse_name(binary_to_list(Ip)).

%% ── Configured resolver ───────────────────────────────────────
%% Returns {ok, {IpTuple, 53}} if ptr_resolver is set and valid, else undefined.
resolver() ->
    case reverse_settings() of
        #{<<"enrichment_enabled">> := true,
          <<"resolvers">> := [#{<<"address">> := Addr, <<"port">> := Port} | _]} ->
            case inet:parse_address(to_list(Addr)) of
                {ok, Tuple} -> {ok, {Tuple, Port}};
                {error, _} -> undefined
            end;
        _ -> undefined
    end.

reverse_settings() ->
    case bifrost_dns_settings_server:effective() of
        {ok, #{settings := #{<<"reverse_dns">> := R}}} -> R;
        _ -> #{}
    end.

visible_provenance() ->
    case resolver() of
        undefined -> <<"__disabled__">>;
        _ -> provenance()
    end.

provenance() ->
    Resolvers = maps:get(<<"resolvers">>, reverse_settings(), []),
    binary:part(binary:encode_hex(crypto:hash(sha256,
        term_to_binary(Resolvers, [deterministic])), lowercase), 0, 32).

%% ── Cache-aware lookup (non-blocking) ─────────────────────────
%% Returns the cached PTR name for an IP (binary) or undefined. If the cache is
%% missing or stale, kicks off an async resolve so the next page load has it —
%% never blocks the caller on live DNS.
cached_name(IpBin) when is_binary(IpBin) ->
    case query_cache(IpBin) of
        {fresh, Name} -> Name;                     %% may be null (negative)
        {stale, Name} -> resolve_async(IpBin), Name;
        miss -> resolve_async(IpBin), undefined
    end.

query_cache(IpBin) ->
    case parse_ip(IpBin) of
        error -> miss;
        IpTuple ->
            case bifrost_db_pool:equery(
                   "SELECT name, EXTRACT(EPOCH FROM (now() - looked_up))::bigint "
                   "FROM ptr_cache WHERE ip = $1 AND provenance = $2", [IpTuple, provenance()]) of
                {ok, _, [{Name, Age}]} ->
                    N = case Name of null -> null; _ -> Name end,
                    {Positive, Negative} = ttl_seconds(),
                    Limit = case N of null -> Negative; _ -> Positive end,
                    case to_int(Age) < Limit of
                        true -> {fresh, N};
                        false -> {stale, N}
                    end;
                _ -> miss
            end
    end.

%% Live resolve + cache write, run in a detached process. Only when a resolver
%% is configured; otherwise a no-op (PTR disabled).
resolve_async(IpBin) when is_binary(IpBin) ->
    case resolver() of
        undefined -> ok;
        {ok, NS} ->
            ensure_inflight(),
            case ets:update_counter(bifrost_ptr_inflight, active, {2, 1, 32, 32}, {active, 0}) of
                32 -> ok;
                _ ->
                    case ets:insert_new(bifrost_ptr_inflight, {IpBin, true}) of
                        true ->
                            Provenance = provenance(),
                            spawn(fun() ->
                                try do_resolve(IpBin, NS, Provenance)
                                after
                                    ets:delete(bifrost_ptr_inflight, IpBin),
                                    ets:update_counter(bifrost_ptr_inflight, active, -1)
                                end
                            end);
                        false -> ets:update_counter(bifrost_ptr_inflight, active, -1)
                    end
            end,
            ok
    end.

%% Background warmer: resolve PTR for recently-active client IPs that are
%% missing or stale in the cache, so names appear on the Dashboard and Query
%% Log without anyone opening the Clients page. No-op if PTR is disabled.
%% Batch-capped to avoid flooding the gateway resolver.
-define(WARM_LIMIT, 100).
warm() ->
    case resolver() of
        undefined -> ok;
        {ok, _NS} ->
            %% Recently-active clients missing or stale (older than TTL) in cache.
            Sql = "SELECT DISTINCT q.client_ip FROM query_log q "
                  "LEFT JOIN ptr_cache p ON q.client_ip = p.ip "
                  "WHERE q.queried_at >= now() - interval '24 hours' "
                  "  AND (p.ip IS NULL OR p.provenance <> $2 OR "
                  "       EXTRACT(EPOCH FROM (now() - p.looked_up)) >= "
                  "       CASE WHEN p.name IS NULL THEN $3 ELSE $1 END) "
                  "LIMIT " ++ integer_to_list(?WARM_LIMIT),
            {Positive, Negative} = ttl_seconds(),
            case bifrost_db_pool:equery(Sql, [Positive, provenance(), Negative]) of
                {ok, _, Rows} when is_list(Rows) ->
                    [resolve_async(list_to_binary(inet:ntoa(Ip))) || {Ip} <- Rows],
                    {ok, length(Rows)};
                _ -> ok
            end
    end.

do_resolve(IpBin, {NsIp, NsPort}, Provenance) ->
    Name = case reverse_name(IpBin) of
        error -> null;
        RevName ->
            case inet_res:resolve(RevName, in, ptr,
                                  [{nameservers, [{NsIp, NsPort}]}], 3000) of
                {ok, Msg} -> first_ptr(inet_dns:msg(Msg, anlist));
                _ -> null
            end
    end,
    case provenance() of
        Provenance -> store(IpBin, Name, Provenance);
        _ -> ok
    end.

first_ptr([]) -> null;
first_ptr([RR | Rest]) ->
    case inet_dns:rr(RR, type) of
        ptr ->
            Data = inet_dns:rr(RR, data),
            list_to_binary(string:trim(Data, trailing, "."));
        _ -> first_ptr(Rest)
    end.

store(IpBin, Name, Provenance) ->
    case parse_ip(IpBin) of
        error -> ok;
        IpTuple ->
            bifrost_db_pool:equery(
              "INSERT INTO ptr_cache (ip, name, looked_up, provenance) VALUES ($1, $2, now(), $3) "
              "ON CONFLICT (ip) DO UPDATE SET name = $2, looked_up = now(), provenance = $3",
              [IpTuple, Name, Provenance])
    end.

%% Re-resolve age in seconds. Runtime-overridable via settings.ptr_ttl_seconds;
%% falls back to the compiled default on missing/invalid values.
ttl_seconds() ->
    R = reverse_settings(),
    {maps:get(<<"positive_ttl_seconds">>, R, ?TTL_DEFAULT),
     maps:get(<<"negative_ttl_seconds">>, R, 300)}.

ensure_inflight() ->
    case ets:whereis(bifrost_ptr_inflight) of
        undefined -> catch ets:new(bifrost_ptr_inflight, [named_table, public, set,
                                                         {write_concurrency, true}]);
        _ -> ok
    end.

%% Effective name given a manual label. Precedence: label > PTR > undefined.
name_for(_IpBin, Label) when is_binary(Label), Label =/= <<>> -> Label;
name_for(IpBin, _Label) ->
    case resolver() =:= undefined orelse cached_name(IpBin) of
        true -> undefined;
        null -> undefined;
        Name -> Name
    end.

%% ── helpers ───────────────────────────────────────────────────
to_list(V) when is_binary(V) -> binary_to_list(V);
to_list(V) when is_list(V) -> V.

to_int(V) when is_integer(V) -> V;
to_int(V) when is_float(V) -> trunc(V);
to_int(V) when is_binary(V) -> binary_to_integer(V);
to_int(V) when is_list(V) -> list_to_integer(V).

parse_ip(Bin) when is_binary(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, Tuple} -> Tuple;
        {error, _} -> error
    end;
parse_ip(_) -> error.

-module(bifrost_rdap).
-behaviour(gen_server).

%% RDAP fetch coordination, one per node. Three jobs:
%%
%%  1. CLAIM. A lookup only happens after this session wins a short lease row in
%%     rdap_cache (claim_sql/0). The claim is one atomic statement, so concurrent
%%     page loads and the analyzer scan, on this pod or any other, never issue
%%     the same registry request twice. Coordination lives in Postgres because
%%     that is where the result lands; no Mnesia, no singleton.
%%
%%  2. PACE. At most one request per ?INTERVAL_MS per registry HOST from this
%%     node, and a 429 pushes that whole registry out by its Retry-After. The
%%     server only hands out reservations; callers sleep on their own process,
%%     so a slow registry never blocks the GenServer.
%%
%%  3. FILL IN THE BACKGROUND. The Clients page never contacts a registry inside
%%     a request: cache misses are enqueue/1'd here (deduplicated, capped) and
%%     fetched by at most ?WORKERS monitored workers, and the page re-polls.
%%
%% Outcomes are stored with a status. ok / not_found / unsupported are final.
%% Anything else (429, 5xx, timeout, unparseable body) is `transient` and
%% becomes due again at retry_at, with exponential backoff (1h doubling, capped
%% at 7d, never earlier than Retry-After). Caching every failure forever ruled out
%% retry storms but meant one 429 removed a domain from age scoring for good.

-export([start_link/0, enqueue/1, fetch/1, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
%% Pure, exported for EUnit and for bifrost_api_handler:rdap_lookup/1.
-export([reserve/4, push_back/4, admit/4, classify/1, registered_on/1, claim_sql/0]).

-define(INTERVAL_MS, 1000).        %% per registry host, per node
-define(MAX_WAIT_MS, 30000).       %% give the claim back rather than wait longer
-define(QUEUE_CAP, 100).
-define(WORKERS, 2).
-define(RATE_LIMIT_DEFAULT_S, 60). %% 429 without a usable Retry-After

-record(state, {pacer = #{} :: #{string() => integer()},
                queue = queue:new() :: queue:queue(binary()),
                members = #{} :: #{binary() => true},      %% queued or in flight
                workers = #{} :: #{reference() => binary()}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Background fill. Fire-and-forget; dropped if already queued/in flight or the
%% queue is full (the next page load re-enqueues whatever is still due).
enqueue(Base) when is_binary(Base) ->
    gen_server:cast(?MODULE, {enqueue, Base}).

status() ->
    gen_server:call(?MODULE, status).

%% Claim, pace, look up, store. Runs on the CALLER's process: the analyzer's
%% scan worker (sync) or one of this server's fill workers (async).
-spec fetch(binary()) -> done | claimed_elsewhere | busy | db_error.
fetch(Base) ->
    case claim(Base) of
        true -> fetch_claimed(Base);
        false -> claimed_elsewhere;
        error -> db_error
    end.

fetch_claimed(Base) ->
    Host = registry_host(Base),
    case acquire(Host) of
        busy ->
            release(Base),
            busy;
        {ok, Wait} ->
            timer:sleep(Wait),
            Result = try lookup(Base)
                     catch C:R ->
                         logger:warning("rdap lookup ~s crashed: ~p:~p", [Base, C, R]),
                         {transient, crashed, undefined}
                     end,
            case Result of
                {transient, rate_limited, RA} when Host =/= undefined ->
                    gen_server:cast(?MODULE, {backoff, Host, rate_limit_seconds(RA)});
                _ -> ok
            end,
            store(Base, Result),
            done
    end.

rate_limit_seconds(undefined) -> ?RATE_LIMIT_DEFAULT_S;
rate_limit_seconds(S) -> S.

lookup(Base) ->
    {M, F, A} = application:get_env(bifrost, rdap_lookup,
                                    {bifrost_api_handler, rdap_lookup, []}),
    apply(M, F, A ++ [Base]).

%% No registry = no network request = nothing to pace.
registry_host(Base) ->
    case bifrost_api_handler:rdap_registry(Base) of
        undefined -> undefined;
        Url ->
            case uri_string:parse(Url) of
                #{host := H} -> H;
                _ -> Url
            end
    end.

%% A missing server must never mean "unpaced": refuse instead.
acquire(undefined) -> {ok, 0};
acquire(Host) ->
    try gen_server:call(?MODULE, {acquire, Host, ?MAX_WAIT_MS}, 5000)
    catch exit:_ -> busy
    end.

%% ── Postgres ─────────────────────────────────────────────────

%% The cross-pod dedupe. Inserts a pending lease for a new domain, or takes over
%% a transient row (or an abandoned lease) once it is due. Final and live-pending
%% rows are untouched, so RETURNING yields a row to exactly one session.
%% `attempts` survives the takeover; it drives the backoff in store/2.
claim_sql() ->
    "INSERT INTO rdap_cache (domain, status, retry_at) "
    "VALUES ($1, 'pending', now() + interval '60 seconds') "
    "ON CONFLICT (domain) DO UPDATE SET status = 'pending', retry_at = EXCLUDED.retry_at "
    "WHERE rdap_cache.status IN ('transient', 'pending') AND rdap_cache.retry_at <= now() "
    "RETURNING domain".

claim(Base) ->
    case bifrost_db_pool:equery(claim_sql(), [Base]) of
        {ok, 1, _, _} -> true;
        {ok, 0, _, _} -> false;
        _ -> error
    end.

%% Could not get a pacing slot in time: hand the lease back, due immediately, so
%% the next caller is not locked out for the rest of the lease.
release(Base) ->
    _ = bifrost_db_pool:equery(
          "UPDATE rdap_cache SET status = 'transient', retry_at = now() "
          "WHERE domain = $1 AND status = 'pending'", [Base]),
    ok.

store(Base, {ok, D}) ->
    _ = bifrost_db_pool:equery(
          "UPDATE rdap_cache SET status = 'ok', registered_on = $2, "
          "  age_days = current_date - $2::date, has_transfer_lock = $3, "
          "  pending_delete = $4, privacy_protected = $5, attempts = 0, "
          "  retry_at = NULL, looked_up = now() "
          "WHERE domain = $1",
          [Base, registered_on(maps:get(registration_date, D, undefined)),
           maps:get(has_transfer_lock, D, undefined),
           maps:get(pending_delete, D, undefined),
           maps:get(privacy_protected, D, undefined)]),
    ok;
store(Base, {final, Status}) when Status =:= not_found; Status =:= unsupported ->
    _ = bifrost_db_pool:equery(
          "UPDATE rdap_cache SET status = $2, registered_on = NULL, age_days = NULL, "
          "  has_transfer_lock = NULL, pending_delete = NULL, privacy_protected = NULL, "
          "  retry_at = NULL, looked_up = now() "
          "WHERE domain = $1",
          [Base, atom_to_binary(Status)]),
    ok;
%% Guarded on status: if our lease expired and another session already stored a
%% final answer, a late failure must not downgrade it.
store(Base, {transient, Reason, RetryAfter}) ->
    logger:info("rdap lookup ~s failed transiently: ~p", [Base, Reason]),
    _ = bifrost_db_pool:equery(
          "UPDATE rdap_cache SET status = 'transient', "
          "  retry_at = now() + make_interval(secs => GREATEST($2::int, "
          "                       LEAST(3600 * power(2, attempts), 604800))), "
          "  attempts = LEAST(attempts + 1, 30), looked_up = now() "
          "WHERE domain = $1 AND status IN ('pending', 'transient')",
          [Base, case RetryAfter of undefined -> 0; S -> S end]),
    ok.

%% ── GenServer ────────────────────────────────────────────────

init([]) ->
    {ok, #state{}}.

handle_call({acquire, Host, MaxWait}, _From, S = #state{pacer = P}) ->
    case reserve(Host, now_ms(), MaxWait, P) of
        busy -> {reply, busy, S};
        {ok, Wait, P2} -> {reply, {ok, Wait}, S#state{pacer = P2}}
    end;
handle_call(status, _From, S = #state{queue = Q, workers = W}) ->
    {reply, #{queued => queue:len(Q), in_flight => map_size(W)}, S};
handle_call(_Req, _From, S) ->
    {reply, ok, S}.

handle_cast({backoff, Host, Secs}, S = #state{pacer = P}) ->
    logger:warning("rdap: ~s rate-limited, pausing ~ps", [Host, Secs]),
    {noreply, S#state{pacer = push_back(Host, Secs, now_ms(), P)}};
handle_cast({enqueue, Base}, S = #state{queue = Q, members = M}) ->
    case admit(Base, Q, M, ?QUEUE_CAP) of
        {ok, Q2, M2} -> {noreply, drain(S#state{queue = Q2, members = M2})};
        _ -> {noreply, S}
    end;
handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({'DOWN', Ref, process, _, _}, S = #state{workers = W, members = M}) ->
    case maps:take(Ref, W) of
        {Base, W2} -> {noreply, drain(S#state{workers = W2, members = maps:remove(Base, M)})};
        error -> {noreply, S}
    end;
handle_info(_Info, S) ->
    {noreply, S}.

drain(S = #state{queue = Q, workers = W}) when map_size(W) < ?WORKERS ->
    case queue:out(Q) of
        {empty, _} -> S;
        {{value, Base}, Q2} ->
            {_Pid, Ref} = spawn_monitor(?MODULE, fetch, [Base]),
            drain(S#state{queue = Q2, workers = W#{Ref => Base}})
    end;
drain(S) ->
    S.

now_ms() -> erlang:monotonic_time(millisecond).

%% ── Pure helpers ─────────────────────────────────────────────

%% Reserve the next request slot for Host. Slots are spaced ?INTERVAL_MS apart
%% and queue up; a wait beyond MaxWaitMs is refused WITHOUT reserving, so a
%% caller that gives up does not push everyone behind it further out.
reserve(Host, NowMs, MaxWaitMs, Pacer) ->
    Next = max(NowMs, maps:get(Host, Pacer, NowMs)),
    Wait = Next - NowMs,
    case Wait > MaxWaitMs of
        true -> busy;
        false -> {ok, Wait, Pacer#{Host => Next + ?INTERVAL_MS}}
    end.

%% Registry said slow down: nothing to that host before NowMs + Secs. Never
%% pulls an existing later reservation earlier.
push_back(Host, Secs, NowMs, Pacer) ->
    Pacer#{Host => max(maps:get(Host, Pacer, NowMs), NowMs + Secs * 1000)}.

admit(Base, Queue, Members, Cap) ->
    case maps:is_key(Base, Members) of
        true -> duplicate;
        false ->
            case queue:len(Queue) >= Cap of
                true -> full;
                false -> {ok, queue:in(Base, Queue), Members#{Base => true}}
            end
    end.

%% httpc result -> outcome. Only a 404 is a final failure; every other non-200
%% is assumed to be the registry's problem, not the domain's, and is retried.
classify({ok, {{_, 200, _}, _, Body}}) -> {ok, Body};
classify({ok, {{_, 404, _}, _, _}}) -> {final, not_found};
classify({ok, {{_, 429, _}, Headers, _}}) -> {transient, rate_limited, retry_after(Headers)};
classify({ok, {{_, Code, _}, Headers, _}}) -> {transient, {http, Code}, retry_after(Headers)};
classify(_) -> {transient, request_failed, undefined}.

%% Delta-seconds only. The HTTP-date form is rare for RDAP and falls back to
%% the computed backoff, which is never shorter than an hour anyway.
retry_after(Headers) ->
    case proplists:get_value("retry-after", Headers) of
        undefined -> undefined;
        V ->
            try list_to_integer(string:trim(V)) of
                N when N >= 0 -> N;
                _ -> undefined
            catch _:_ -> undefined
            end
    end.

%% RDAP eventDate ("2024-01-15T00:00:00Z") -> {Y, M, D} for a DATE column.
registered_on(<<Y:4/binary, "-", M:2/binary, "-", D:2/binary, _/binary>>) ->
    try
        Date = {binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)},
        true = calendar:valid_date(Date),
        Date
    catch _:_ -> undefined
    end;
registered_on(_) ->
    undefined.

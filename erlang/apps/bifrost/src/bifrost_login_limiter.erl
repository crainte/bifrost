%% Per-address limit on failed logins. After ?MAX_FAILURES failures inside
%% ?WINDOW_SECONDS, that address is refused (429) until the window passes, even
%% with correct credentials, so an online guesser learns nothing more. A
%% successful login clears the address's count.
%%
%% Each attempt costs ~100ms of PBKDF2 CPU in the same container as the DNS
%% resolver, so unthrottled guessing was also a way to starve DNS.
-module(bifrost_login_limiter).
-behaviour(gen_server).

-export([start_link/0, allowed/1, failed/1, succeeded/1, reset/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(TABLE, bifrost_login_failures).
-define(MAX_FAILURES, 10).
-define(WINDOW_SECONDS, 300).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Reads go straight to the table (no call). If the limiter is not running the
%% login still works: fail open, rather than locking the operator out.
-spec allowed(term()) -> boolean().
allowed(Addr) ->
    Now = erlang:system_time(second),
    try ets:lookup(?TABLE, Addr) of
        [{_, Count, First}] when Count >= ?MAX_FAILURES, Now - First < ?WINDOW_SECONDS -> false;
        _ -> true
    catch error:badarg -> true
    end.

failed(Addr) ->
    Now = erlang:system_time(second),
    try
        case ets:lookup(?TABLE, Addr) of
            [{_, Count, First}] when Now - First < ?WINDOW_SECONDS ->
                ets:insert(?TABLE, {Addr, Count + 1, First});
            _ ->
                ets:insert(?TABLE, {Addr, 1, Now})
        end,
        ok
    catch error:badarg -> ok
    end.

succeeded(Addr) ->
    catch ets:delete(?TABLE, Addr),
    ok.

reset() ->
    catch ets:delete_all_objects(?TABLE),
    ok.

init([]) ->
    ets:new(?TABLE, [named_table, public, set, {write_concurrency, true}]),
    erlang:send_after(?WINDOW_SECONDS * 1000, self(), sweep),
    {ok, #{}}.

handle_call(_Request, _From, State) -> {reply, ok, State}.
handle_cast(_Msg, State) -> {noreply, State}.

%% Drop expired windows, so an attacker cycling through many source addresses
%% (trivial with IPv6) cannot grow the table without bound.
handle_info(sweep, State) ->
    Cutoff = erlang:system_time(second) - ?WINDOW_SECONDS,
    ets:select_delete(?TABLE, [{{'_', '_', '$1'}, [{'<', '$1', Cutoff}], [true]}]),
    erlang:send_after(?WINDOW_SECONDS * 1000, self(), sweep),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

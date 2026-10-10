-module(bifrost_db_pool).
-behaviour(gen_server).

-export([start_link/0, start_link/1, query/1, query/2, equery/2, equery/3, is_connected/0,
         pool_query/3, pool_equery/4]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(RECONNECT_DELAY, 2000).
-define(CALL_TIMEOUT, 30000).
%% Server-side cap on any one statement. The pool is a single connection, so one
%% runaway query would otherwise stall every caller behind it indefinitely.
-define(STATEMENT_TIMEOUT, "20s").
%% Postgres rejected the STATEMENT (bad value, constraint, syntax) and said so:
%% the connection is fine. Reconnecting on these made one malformed row fail
%% every query that followed it while the pool re-established the connection.
%% epgsql reports them as its #error{} record: {error, Severity, Code, ...}.
-define(IS_SQL_ERROR(E), (is_tuple(E) andalso tuple_size(E) =:= 6 andalso element(1, E) =:= error)).

-record(state, {
    name :: atom(),
    conn :: term() | undefined,
    host :: string(),
    port :: integer(),
    dbname :: string(),
    user :: string(),
    password :: string(),
    migrated = false :: boolean()
}).

start_link() ->
    start_link(?MODULE).

%% A second, independently-named connection. The query writer uses its own so
%% per-query logging never queues behind a slow dashboard query on the shared
%% pool (and vice versa). Only the default pool runs migrations.
start_link(Name) ->
    gen_server:start_link({local, Name}, ?MODULE, [Name], []).

query(Sql) ->
    query(Sql, ?CALL_TIMEOUT).

%% With an explicit timeout the CALLER gives up (and gets {error, timeout})
%% instead of exiting: hydration uses this so a hung Postgres costs seconds and
%% falls back to the Mnesia snapshot, rather than blocking DNS readiness.
query(Sql, Timeout) ->
    pool_query(?MODULE, Sql, Timeout).

equery(Sql, Params) ->
    equery(Sql, Params, ?CALL_TIMEOUT).

equery(Sql, Params, Timeout) ->
    pool_equery(?MODULE, Sql, Params, Timeout).

pool_query(Pool, Sql, Timeout) ->
    call(Pool, {query, Sql}, Timeout).

pool_equery(Pool, Sql, Params, Timeout) ->
    call(Pool, {equery, Sql, Params}, Timeout).

call(Pool, Request, Timeout) ->
    try gen_server:call(Pool, Request, Timeout)
    catch exit:{timeout, _} -> {error, timeout};
          exit:{noproc, _} -> {error, not_connected}
    end.

%% Last known connection state, readable without a call. Readiness reports it
%% for observability only and must never block on (or depend on) Postgres.
is_connected() ->
    persistent_term:get({?MODULE, connected}, false).

set_connected(Bool) ->
    Key = {get(pool_name), connected},
    case persistent_term:get(Key, undefined) of
        Bool -> ok;
        _ -> persistent_term:put(Key, Bool)
    end.

init([Name]) ->
    logger:info("~s (~p) started", [?MODULE, Name]),
    put(pool_name, Name),
    %% epgsql LINKS its socket process to this one. A failed connect makes that
    %% process exit with the connection error, and without trap_exit the link
    %% kills this GenServer even though epgsql:connect/4 also returned a clean
    %% {error, _} we already handle. bifrost_sup then restarted us 5 times inside
    %% a few MILLISECONDS, hit reached_max_restart_intensity, and shut down the
    %% whole application — so a Postgres outage took the entire DNS cluster down
    %% with it. Postgres is control-plane only; DNS must survive losing it.
    process_flag(trap_exit, true),
    set_connected(false),
    Config = case catch bifrost_config_server:get_config() of
        {ok, C} -> C;
        _ -> #{}
    end,
    DB = case maps:find(database, Config) of
        {ok, D} when is_list(D) -> D;
        _ -> []
    end,
    Host = proplists:get_value(host, DB, "postgres"),
    Port = proplists:get_value(port, DB, 5432),
    DbName = proplists:get_value(name, DB, "bifrost"),
    User = proplists:get_value(user, DB, "bifrost"),
    %% Password precedence: BIFROST_DB_PASSWORD env (injected from a k8s Secret
    %% in production) over the config term (dev convenience). Never log it.
    Password = case os:getenv("BIFROST_DB_PASSWORD") of
        false -> proplists:get_value(password, DB, "bifrost");
        ""    -> proplists:get_value(password, DB, "bifrost");
        EnvPw -> EnvPw
    end,
    State = #state{name = Name, host = Host, port = Port, dbname = DbName,
                   user = User, password = Password,
                   migrated = Name =/= ?MODULE},
    self() ! connect,
    {ok, State}.

handle_call({query, Sql}, _From, State = #state{conn = Conn}) when Conn =/= undefined ->
    case epgsql:squery(Conn, Sql) of
        {ok, _, _} = Result -> {reply, Result, State};
        {ok, _} = Result -> {reply, Result, State};
        {error, Error} = Result when ?IS_SQL_ERROR(Error) -> {reply, Result, State};
        {error, Error} ->
            logger:warning("query failed: ~p, reconnecting", [Error]),
            self() ! connect,
            set_connected(false),
            {reply, {error, Error}, State#state{conn = undefined}}
    end;
handle_call({query, _Sql}, _From, State) ->
    {reply, {error, not_connected}, State};

%% A bad parameter is a CALLER bug that must not cost the whole pool. epgsql
%% encodes parameters inside its socket process, and a type mismatch (a binary
%% bound to an inet column, say) raises function_clause THERE — killing the socket
%% and exiting the gen_server:call we are blocked in, so the pool dies for one
%% malformed request and every other caller's next query fails too. trap_exit does
%% not help: the exit arrives as the result of our own call, not as a signal.
%% Caught here, the offending request gets an error and everyone else is unharmed.
handle_call({equery, Sql, Params}, _From, State = #state{conn = Conn}) when Conn =/= undefined ->
    try epgsql:equery(Conn, Sql, Params) of
        {ok, Count, Cols, Rows} -> {reply, {ok, Count, Cols, Rows}, State};  %% INSERT/UPDATE RETURNING
        {ok, Cols, Rows} -> {reply, {ok, Cols, Rows}, State};                %% SELECT
        {ok, Count} -> {reply, {ok, Count}, State};                          %% INSERT/UPDATE/DELETE
        {error, Error} = Result when ?IS_SQL_ERROR(Error) -> {reply, Result, State};
        {error, Error} ->
            logger:warning("equery failed: ~p, reconnecting", [Error]),
            self() ! connect,
            set_connected(false),
            {reply, {error, Error}, State#state{conn = undefined}}
    catch Class:Reason ->
        %% The connection process is gone, so reconnect as in the error branch.
        logger:error("equery raised ~p:~p (bad parameter type?) sql=~s params=~p",
                     [Class, Reason, Sql, Params]),
        self() ! connect,
        set_connected(false),
        {reply, {error, {equery_raised, Reason}}, State#state{conn = undefined}}
    end;
handle_call({equery, _Sql, _Params}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(connect, State = #state{host = H, port = P, dbname = D, user = U, password = PW}) ->
    logger:info("connecting to Postgres at ~s:~p/~s", [H, P, D]),
    %% epgsql 4.7 connect options: host, username, password, [{port, P}, {database, D}, {timeout, T}]
    case epgsql:connect(H, U, PW, [{port, P}, {database, D}, {timeout, 5000}]) of
        {ok, Conn} ->
            logger:info("connected to Postgres"),
            NewState = State#state{conn = Conn},
            Migrated = case State#state.migrated of
                false -> bifrost_migrations:run(Conn), true;
                true -> true
            end,
            _ = epgsql:squery(Conn, "SET statement_timeout = '" ?STATEMENT_TIMEOUT "'"),
            set_connected(true),
            {noreply, NewState#state{migrated = Migrated}};
        {error, Reason} ->
            logger:warning("Postgres connection failed: ~p, retrying in ~p ms",
                           [Reason, ?RECONNECT_DELAY]),
            erlang:send_after(?RECONNECT_DELAY, self(), connect),
            {noreply, State}
    end;
handle_info({epgsql, Conn, {closed, _}}, State = #state{conn = Conn}) ->
    logger:warning("Postgres connection closed, reconnecting"),
    set_connected(false),
    erlang:send_after(?RECONNECT_DELAY, self(), connect),
    {noreply, State#state{conn = undefined}};
%% The linked epgsql socket process died. Two cases, neither fatal:
%%  - it was our live connection: drop it and reconnect on a timer;
%%  - it was a failed connect attempt whose {error, _} we already handled and
%%    scheduled a retry for, so there is nothing left to do.
handle_info({'EXIT', Pid, Reason}, State = #state{conn = Pid}) ->
    logger:warning("Postgres connection process exited: ~p, reconnecting", [Reason]),
    set_connected(false),
    erlang:send_after(?RECONNECT_DELAY, self(), connect),
    {noreply, State#state{conn = undefined}};
handle_info({'EXIT', _Pid, _Reason}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% Login / logout endpoints. GET /login renders a form; POST /login verifies the
%% admin credentials and, on success, sets a signed session cookie. POST /logout
%% clears it. These routes are exempt from the auth middleware (you must be able
%% to reach the login page while unauthenticated) — see bifrost_auth_middleware.
-module(bifrost_auth_handler).

-export([init/2]).

-define(CT_HTML, #{<<"content-type">> => <<"text/html; charset=utf-8">>}).
-define(COOKIE, <<"bifrost_session">>).

init(Req0, login) ->
    handle_login(cowboy_req:method(Req0), Req0);
init(Req0, logout) ->
    handle_logout(cowboy_req:method(Req0), Req0).

%% ── Login ─────────────────────────────────────────────────────

handle_login(<<"GET">>, Req0) ->
    reply_login_page(Req0, undefined);
handle_login(<<"POST">>, Req0) ->
    {PeerIp, _} = cowboy_req:peer(Req0),
    case bifrost_login_limiter:allowed(PeerIp) of
        true -> attempt_login(PeerIp, Req0);
        false ->
            logger:warning("login refused for ~s: too many failed attempts", [inet:ntoa(PeerIp)]),
            Req1 = cowboy_req:reply(429, ?CT_HTML,
                                    login_html(<<"Too many failed attempts. Try again in a few minutes.">>),
                                    Req0),
            {ok, Req1, []}
    end;
handle_login(_, Req0) ->
    Req1 = cowboy_req:reply(405, Req0),
    {ok, Req1, []}.

attempt_login(PeerIp, Req0) ->
    {ok, KVs, Req1} = cowboy_req:read_urlencoded_body(Req0),
    User = proplists:get_value(<<"username">>, KVs, <<>>),
    Pass = proplists:get_value(<<"password">>, KVs, <<>>),
    case bifrost_auth:check_credentials(User, Pass) of
        true ->
            bifrost_login_limiter:succeeded(PeerIp),
            Token = bifrost_auth:make_token(),
            Req2 = set_session_cookie(Req1, Token),
            %% 303 so the browser re-GETs the dashboard (POST-redirect-GET).
            Req3 = cowboy_req:reply(303, #{<<"location">> => <<"/dashboard">>}, Req2),
            {ok, Req3, []};
        false ->
            %% Uniform response — never reveal whether the user or the password
            %% was wrong. The log is server-side only, so naming the user here
            %% leaks nothing to the client but makes brute force visible.
            bifrost_login_limiter:failed(PeerIp),
            logger:warning("failed login for ~ts from ~s",
                           [User, inet:ntoa(PeerIp)]),
            %% Small delay blunts online brute force.
            timer:sleep(500),
            reply_login_page(Req1, <<"Invalid username or password.">>)
    end.

%% ── Logout ────────────────────────────────────────────────────

handle_logout(<<"POST">>, Req0) ->
    Req1 = clear_session_cookie(Req0),
    Req2 = cowboy_req:reply(303, #{<<"location">> => <<"/login">>}, Req1),
    {ok, Req2, []};
handle_logout(_, Req0) ->
    Req1 = cowboy_req:reply(405, Req0),
    {ok, Req1, []}.

%% ── Cookies ───────────────────────────────────────────────────
%% HttpOnly (no JS access -> XSS can't steal it), SameSite=Lax (CSRF defense),
%% Path=/, Max-Age=TTL, and Secure whenever the CLIENT used HTTPS: directly, or
%% via a TLS-terminating ingress that reports it in X-Forwarded-Proto. (The app
%% itself sees plain HTTP behind an ingress, so Secure cannot be forced blindly
%% without locking out plain-HTTP home setups.) Trusting the header here only
%% ever ADDS a restriction, so a spoofed header gains an attacker nothing.
set_session_cookie(Req, Token) ->
    cowboy_req:set_resp_cookie(?COOKIE, Token, Req, cookie_opts(Req, bifrost_auth:session_ttl())).

clear_session_cookie(Req) ->
    cowboy_req:set_resp_cookie(?COOKIE, <<"">>, Req, cookie_opts(Req, 0)).

cookie_opts(Req, MaxAge) ->
    #{http_only => true, same_site => lax, path => <<"/">>, max_age => MaxAge,
      secure => client_used_https(Req)}.

client_used_https(Req) ->
    cowboy_req:scheme(Req) =:= <<"https">> orelse
        string:lowercase(cowboy_req:header(<<"x-forwarded-proto">>, Req, <<>>)) =:= <<"https">>.

%% ── Login page ────────────────────────────────────────────────

reply_login_page(Req0, Error) ->
    Html = login_html(Error),
    Req1 = cowboy_req:reply(200, ?CT_HTML, Html, Req0),
    {ok, Req1, []}.

login_html(Error) ->
    ErrBlock = case Error of
        undefined -> <<"">>;
        Msg -> <<"<div class=\"login-error\" role=\"alert\">",
                  (esc(Msg))/binary, "</div>">>
    end,
    <<"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
       "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
       "<title>Bifrost - Sign in</title><link rel=\"icon\" type=\"image/png\" href=\"/static/bifrost-icon.png\">",
       "<link rel=\"stylesheet\" href=\"/static/bifrost.css\"></head>",
       "<body class=\"login-page\"><form method=\"post\" action=\"/login\" class=\"login-card\">",
       "<img src=\"/static/bifrost-wordmark.png\" class=\"login-brand\" alt=\"Bifrost DNS\">",
       "<p class=\"page-subtitle\">DNS operations for your network</p>",
       ErrBlock/binary,
       "<label for=\"username\">Username</label><input id=\"username\" name=\"username\" autocomplete=\"username\" autofocus required>",
       "<label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>",
       "<button type=\"submit\" class=\"button-primary\">Sign in</button>",
       "</form></body></html>">>.

esc(Bin) ->
    binary:replace(
      binary:replace(
        binary:replace(Bin, <<"&">>, <<"&amp;">>, [global]),
        <<"<">>, <<"&lt;">>, [global]),
      <<">">>, <<"&gt;">>, [global]).

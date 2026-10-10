%% Cowboy middleware that authenticates every request before it reaches a
%% handler. Runs after the router (so cowboy_req:path/1 is set) and before the
%% handler. Accepts either a valid signed session cookie (browser) or HTTP Basic
%% credentials (API clients).
%%
%% Fail-closed: if auth is not fully configured (missing admin/secret env), every
%% gated route is refused (503) rather than served open.
%%
%% Exempt (never require auth):
%%   /api/health     — k8s readiness probe, must answer unauthenticated
%%   /api/health/live — k8s liveness/startup probe, ditto
%%   /login          — you must reach the form while logged out
%%   /logout         — clearing a cookie needs no auth
-module(bifrost_auth_middleware).
-behaviour(cowboy_middleware).

-export([execute/2]).

-define(COOKIE, <<"bifrost_session">>).

execute(Req, Env) ->
    Path = cowboy_req:path(Req),
    case cross_site_write(Req) of
        true ->
            {stop, reply_json(Req, 403, #{error => <<"cross-site request refused">>})};
        false ->
            case is_exempt(Path) of
                true -> {ok, Req, Env};
                false -> gate(Req, Env, Path)
            end
    end.

%% Browsers attach cookies AND cached Basic credentials to cross-site requests,
%% so SameSite=Lax alone did not stop a malicious page from POSTing to the API
%% with an operator's Basic auth. Any state-changing request a browser marks as
%% coming from another site — Fetch Metadata, or an Origin that is not this
%% host — is refused. Non-browser clients (curl, scripts) send neither header
%% and are unaffected.
cross_site_write(Req) ->
    case lists:member(cowboy_req:method(Req), [<<"GET">>, <<"HEAD">>, <<"OPTIONS">>]) of
        true -> false;
        false ->
            cowboy_req:header(<<"sec-fetch-site">>, Req) =:= <<"cross-site">>
                orelse foreign_origin(Req)
    end.

foreign_origin(Req) ->
    case cowboy_req:header(<<"origin">>, Req) of
        undefined -> false;
        <<"null">> -> true;
        Origin ->
            case uri_string:parse(Origin) of
                #{host := Host} = U ->
                    Port = maps:get(port, U, default_port(maps:get(scheme, U, <<"http">>))),
                    {Host, Port} =/= {cowboy_req:host(Req), cowboy_req:port(Req)}
                        andalso not same_host_header(Origin, Req);
                _ -> true
            end
    end.

%% Behind a proxy the request host/port Cowboy sees may differ from what the
%% browser used; the Host header carries what the browser addressed.
same_host_header(Origin, Req) ->
    case cowboy_req:header(<<"host">>, Req) of
        undefined -> false;
        HostHdr ->
            #{host := OH} = OU = uri_string:parse(Origin),
            OPort = maps:get(port, OU, default_port(maps:get(scheme, OU, <<"http">>))),
            case binary:split(HostHdr, <<":">>) of
                [H, P] -> {OH, OPort} =:= {H, binary_to_integer(P)};
                [H] -> OH =:= H andalso lists:member(OPort, [80, 443])
            end
    end.

default_port(<<"https">>) -> 443;
default_port(_) -> 80.

is_exempt(<<"/api/health">>) -> true;
is_exempt(<<"/api/health/live">>) -> true;
is_exempt(<<"/login">>) -> true;
is_exempt(<<"/logout">>) -> true;
is_exempt(<<"/static/bifrost-icon.png">>) -> true;
is_exempt(<<"/static/bifrost-wordmark.png">>) -> true;
is_exempt(<<"/static/bifrost.css">>) -> true;
is_exempt(_) -> false.

gate(Req, Env, Path) ->
    case bifrost_auth:configured() of
        false ->
            %% Misconfigured deploy: refuse rather than serve open. Loud + safe.
            {stop, reply_json(Req, 503,
                #{error => <<"authentication not configured">>})};
        true ->
            case authenticated(Req) of
                true -> {ok, Req, Env};
                false -> deny(Req, Path)
            end
    end.

%% Session cookie first (the common browser path), then Basic auth (API clients).
authenticated(Req) ->
    case valid_cookie(Req) of
        true -> true;
        false -> valid_basic(Req)
    end.

valid_cookie(Req) ->
    Cookies = cowboy_req:parse_cookies(Req),
    case lists:keyfind(?COOKIE, 1, Cookies) of
        {_, Token} ->
            case bifrost_auth:verify_token(Token) of
                {ok, _Expiry} -> true;
                {error, _} -> false
            end;
        false -> false
    end.

valid_basic(Req) ->
    case cowboy_req:parse_header(<<"authorization">>, Req) of
        {basic, User, Pass} -> bifrost_auth:check_credentials(User, Pass);
        _ -> false
    end.

%% API clients get a 401 (JSON, with a Basic challenge). Browser page loads get a
%% 302 to the login form. Heuristic: /api/* and non-GET are "API".
deny(Req, <<"/api/", _/binary>>) ->
    {stop, reply_unauthorized(Req)};
deny(Req, _Path) ->
    case cowboy_req:method(Req) of
        <<"GET">> ->
            {stop, cowboy_req:reply(302, #{<<"location">> => <<"/login">>}, Req)};
        _ ->
            {stop, reply_unauthorized(Req)}
    end.

reply_unauthorized(Req) ->
    cowboy_req:reply(401,
        #{<<"content-type">> => <<"application/json">>,
          <<"www-authenticate">> => <<"Basic realm=\"bifrost\"">>},
        jsx:encode(#{error => <<"unauthorized">>}), Req).

reply_json(Req, Code, Body) ->
    cowboy_req:reply(Code,
        #{<<"content-type">> => <<"application/json">>},
        jsx:encode(Body), Req).

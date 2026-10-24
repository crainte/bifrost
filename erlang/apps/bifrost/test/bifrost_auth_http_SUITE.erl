%% End-to-end Common Test suite for the auth middleware over real HTTP. Starts a
%% Cowboy listener with the SAME middleware chain the app uses
%% ([cowboy_router, bifrost_auth_middleware, cowboy_handler]) plus the real
%% bifrost_auth_handler for /login|/logout and a trivial protected handler, then
%% drives it with httpc. This proves the actual on-the-wire gate: exemptions,
%% 401 vs 302 behavior, the login->cookie->access flow, Basic auth, and
%% fail-closed when unconfigured.
-module(bifrost_auth_http_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).
-export([health_is_exempt/1, static_assets_are_exempt/1,
          gated_api_401_without_auth/1, expired_browser_fetch_has_no_basic_challenge/1,
          gated_page_redirects_to_login/1, login_bad_creds_no_cookie/1,
         login_good_creds_sets_cookie/1, cookie_grants_access/1,
         basic_auth_grants_api/1, logout_clears_cookie/1,
         unconfigured_fails_closed/1,
         login_over_https_sets_secure_cookie/1,
         login_over_plain_http_has_no_secure_flag/1,
         cross_origin_write_is_refused/1,
         cross_site_fetch_metadata_is_refused/1,
         same_origin_write_is_allowed/1,
         repeated_failed_logins_are_rate_limited/1]).
-export([init/2]).   % cowboy handler entrypoint for the test handlers

-define(PORT, 18099).
-define(USER, "admin").
-define(PASS, "hunter2").

all() ->
    [health_is_exempt, static_assets_are_exempt, gated_api_401_without_auth,
     expired_browser_fetch_has_no_basic_challenge,
     gated_page_redirects_to_login, login_bad_creds_no_cookie, login_good_creds_sets_cookie, cookie_grants_access,
     basic_auth_grants_api, logout_clears_cookie, unconfigured_fails_closed,
     login_over_https_sets_secure_cookie, login_over_plain_http_has_no_secure_flag,
     cross_origin_write_is_refused, cross_site_fetch_metadata_is_refused,
     same_origin_write_is_allowed, repeated_failed_logins_are_rate_limited].

init_per_suite(Config) ->
    application:ensure_all_started(cowboy),
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    {ok, Limiter} = bifrost_login_limiter:start_link(),
    unlink(Limiter),
    Dispatch = cowboy_router:compile([{'_', [
        {"/login",  bifrost_auth_handler, login},
        {"/logout", bifrost_auth_handler, logout},
        {"/api/health", ?MODULE, health},   % exempt, mimics real health route
         {"/static/bifrost-icon.png", cowboy_static, {priv_file, bifrost, "static/bifrost-icon.png"}},
         {"/static/bifrost-wordmark.png", cowboy_static, {priv_file, bifrost, "static/bifrost-wordmark.png"}},
         {"/static/bifrost.css", cowboy_static, {priv_file, bifrost, "static/bifrost.css"}},
        {"/api/thing", ?MODULE, protected}, % gated /api/*
        {"/dashboard", ?MODULE, protected}  % gated page
    ]}]),
    {ok, _} = cowboy:start_clear(auth_test_listener,
        [{port, ?PORT}],
        #{env => #{dispatch => Dispatch},
          middlewares => [cowboy_router, bifrost_auth_middleware, cowboy_handler]}),
    Config.

end_per_suite(_Config) ->
    cowboy:stop_listener(auth_test_listener),
    catch gen_server:stop(bifrost_login_limiter),
    ok.

%% Most tests want auth fully configured; unconfigured_fails_closed clears it.
init_per_testcase(unconfigured_fails_closed, Config) ->
    clear_auth_env(), Config;
init_per_testcase(_TC, Config) ->
    bifrost_login_limiter:reset(),
    set_auth_env(), Config.

end_per_testcase(_TC, _Config) ->
    clear_auth_env(), ok.

%% ── Exemptions ────────────────────────────────────────────────

%% /api/health answers 200 with no credentials (k8s probes).
health_is_exempt(_) ->
    {Code, _H, _B} = req(get, "/api/health", [], undefined),
    ?assertEqual(200, Code).

static_assets_are_exempt(_) ->
    {IconCode, _IconH, _IconB} = req(get, "/static/bifrost-icon.png", [], undefined),
    {WordmarkCode, WordmarkH, WordmarkB} = req(get, "/static/bifrost-wordmark.png", [], undefined),
    {CssCode, CssH, CssBody} = req(get, "/static/bifrost.css", [], undefined),
    ?assertEqual(200, IconCode),
    ?assertEqual(200, WordmarkCode),
    ?assertMatch("image/png" ++ _, proplists:get_value("content-type", WordmarkH, "")),
    ?assert(iolist_size(WordmarkB) > 0),
    ?assertEqual(200, CssCode),
    ?assertMatch("text/css" ++ _, proplists:get_value("content-type", CssH, "")),
    ?assert(iolist_size(CssBody) > 100).

%% ── Gating ────────────────────────────────────────────────────

%% A gated /api/* route without auth is 401 (JSON) + a Basic challenge header.
gated_api_401_without_auth(_) ->
    {Code, H, _B} = req(get, "/api/thing", [], undefined),
    ?assertEqual(401, Code),
    ?assertMatch("Basic" ++ _, proplists:get_value("www-authenticate", H, "")).

%% A browser fetch with an expired cookie must not trigger the browser's native
%% Basic auth modal; it needs a plain 401 so the UI can navigate to /login.
expired_browser_fetch_has_no_basic_challenge(_) ->
    Expired = binary_to_list(bifrost_auth:make_token(0)),
    Headers = [{"cookie", "bifrost_session=" ++ Expired},
               {"sec-fetch-mode", "cors"}],
    {Code, H, _B} = req(get, "/api/thing", Headers, undefined),
    ?assertEqual(401, Code),
    ?assertEqual(undefined, proplists:get_value("www-authenticate", H)),
    {PostCode, PostH, _} = req(post, "/api/thing",
                               [{"content-type", "application/json"} | Headers], "{}"),
    ?assertEqual(401, PostCode),
    ?assertEqual(undefined, proplists:get_value("www-authenticate", PostH)),
    {SameOriginCode, SameOriginH, _} =
        req(get, "/api/thing", [{"cookie", "bifrost_session=" ++ Expired},
                                {"sec-fetch-mode", "same-origin"}], undefined),
    ?assertEqual(401, SameOriginCode),
    ?assertEqual(undefined, proplists:get_value("www-authenticate", SameOriginH)).

%% A gated PAGE without auth redirects to /login (302), not a 401.
gated_page_redirects_to_login(_) ->
    {Code, H, _B} = req(get, "/dashboard", [], undefined),
    ?assertEqual(302, Code),
    ?assertEqual("/login", proplists:get_value("location", H)).

%% ── Login flow ────────────────────────────────────────────────

%% Wrong credentials: no session cookie is set, response is the branded login page.
login_bad_creds_no_cookie(_) ->
    Body = "username=admin&password=wrong",
    {Code, H, B} = req(post, "/login", form_headers(), Body),
    ?assertEqual(200, Code),
    ?assertEqual(undefined, proplists:get_value("set-cookie", H)),
    Html = iolist_to_binary(B),
    ?assertNotEqual(nomatch, binary:match(Html, <<"/static/bifrost-wordmark.png">>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"/static/bifrost.css">>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"role=\"alert\"">>)).

%% Correct credentials: 303 redirect to /dashboard + a Set-Cookie session token.
login_good_creds_sets_cookie(_) ->
    {Code, H, _B} = do_login(),
    ?assertEqual(303, Code),
    ?assertEqual("/dashboard", proplists:get_value("location", H)),
    ?assertMatch("bifrost_session=" ++ _, proplists:get_value("set-cookie", H)).

%% The cookie from a successful login grants access to a gated page (200).
cookie_grants_access(_) ->
    {303, H, _} = do_login(),
    Cookie = cookie_kv(proplists:get_value("set-cookie", H)),
    {Code, _H, _B} = req(get, "/dashboard", [{"cookie", Cookie}], undefined),
    ?assertEqual(200, Code).

%% HTTP Basic with correct creds authenticates an /api/* request (for clients).
basic_auth_grants_api(_) ->
    B64 = base64:encode_to_string(?USER ++ ":" ++ ?PASS),
    {Code, _H, _B} = req(get, "/api/thing", [{"authorization", "Basic " ++ B64}], undefined),
    ?assertEqual(200, Code).

%% Logout clears the cookie (Set-Cookie with an empty/expired value).
logout_clears_cookie(_) ->
    {303, H, _} = do_login(),
    Cookie = cookie_kv(proplists:get_value("set-cookie", H)),
    {Code, LH, _} = req(post, "/logout", [{"cookie", Cookie}], <<>>),
    ?assertEqual(303, Code),
    SetCookie = proplists:get_value("set-cookie", LH),
    ?assertMatch("bifrost_session=" ++ _, SetCookie),
    %% Cleared cookie carries an expiry in the past / empty value.
    ?assert(string:find(SetCookie, "bifrost_session=;") =/= nomatch
            orelse string:find(SetCookie, "Max-Age=0") =/= nomatch).

%% ── Fail-closed ───────────────────────────────────────────────

%% With no admin/secret configured, every gated route is 503 — never served open.
unconfigured_fails_closed(_) ->
    {Code, _H, _B} = req(get, "/api/thing", [], undefined),
    ?assertEqual(503, Code),
    %% Health stays reachable even unconfigured.
    {HCode, _, _} = req(get, "/api/health", [], undefined),
    ?assertEqual(200, HCode).

%% ── Transport + cross-site protections ────────────────────────

%% Behind a TLS-terminating ingress the app sees plain HTTP; the ingress says
%% the client used HTTPS via X-Forwarded-Proto. The session cookie must then be
%% Secure so it is never sent over plain HTTP.
login_over_https_sets_secure_cookie(_) ->
    {303, H, _} = req(post, "/login", [{"x-forwarded-proto", "https"} | form_headers()],
                      "username=" ++ ?USER ++ "&password=" ++ ?PASS),
    ?assertNotEqual(nomatch, string:find(string:lowercase(proplists:get_value("set-cookie", H)),
                                         "secure")).

login_over_plain_http_has_no_secure_flag(_) ->
    {303, H, _} = do_login(),
    ?assertEqual(nomatch, string:find(string:lowercase(proplists:get_value("set-cookie", H)),
                                      "secure")).

%% Browsers attach cached Basic credentials to cross-site requests, so SameSite
%% cookies alone do not stop a malicious page from POSTing to the API.
cross_origin_write_is_refused(_) ->
    {Code, _, _} = req(post, "/api/thing", [basic(), {"origin", "http://evil.example"},
                                            {"content-type", "application/json"}], "{}"),
    ?assertEqual(403, Code).

cross_site_fetch_metadata_is_refused(_) ->
    {Code, _, _} = req(post, "/api/thing", [basic(), {"sec-fetch-site", "cross-site"},
                                            {"content-type", "application/json"}], "{}"),
    ?assertEqual(403, Code).

same_origin_write_is_allowed(_) ->
    {Code, _, _} = req(post, "/api/thing", [basic(), {"origin", "http://127.0.0.1:" ++ integer_to_list(?PORT)},
                                            {"sec-fetch-site", "same-origin"},
                                            {"content-type", "application/json"}], "{}"),
    ?assertEqual(200, Code),
    %% Non-browser clients (curl, scripts) send no Origin at all.
    {Code2, _, _} = req(post, "/api/thing", [basic(), {"content-type", "application/json"}], "{}"),
    ?assertEqual(200, Code2).

%% Online brute force: after repeated failures from one address, even correct
%% credentials are refused for a while (so the attacker learns nothing).
repeated_failed_logins_are_rate_limited(_) ->
    [req(post, "/login", form_headers(), "username=admin&password=wrong" ++ integer_to_list(N))
     || N <- lists:seq(1, 10)],
    {Code, H, _} = do_login(),
    ?assertEqual(429, Code),
    ?assertEqual(undefined, proplists:get_value("set-cookie", H)).

basic() ->
    {"authorization", "Basic " ++ base64:encode_to_string(?USER ++ ":" ++ ?PASS)}.

%% ── Minimal handlers under test ───────────────────────────────

init(Req0, health) ->
    {ok, cowboy_req:reply(200, #{}, <<"ok">>, Req0), health};
init(Req0, protected) ->
    {ok, cowboy_req:reply(200, #{}, <<"secret">>, Req0), protected}.


%% ── helpers ───────────────────────────────────────────────────

set_auth_env() ->
    os:putenv("BIFROST_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
    os:putenv("BIFROST_ADMIN_USER", ?USER),
    os:putenv("BIFROST_ADMIN_PASSWORD_HASH",
              binary_to_list(bifrost_auth:hash_password(list_to_binary(?PASS)))).

clear_auth_env() ->
    os:unsetenv("BIFROST_SESSION_SECRET"),
    os:unsetenv("BIFROST_ADMIN_USER"),
    os:unsetenv("BIFROST_ADMIN_PASSWORD_HASH").

do_login() ->
    req(post, "/login", form_headers(), "username=" ++ ?USER ++ "&password=" ++ ?PASS).

form_headers() -> [{"content-type", "application/x-www-form-urlencoded"}].

url(Path) -> "http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path.

%% httpc wrapper: no autoredirect (so we observe 302/303), lowercased headers.
req(get, Path, Headers, _Body) ->
    do_req({url(Path), Headers});
req(post, Path, Headers, Body) ->
    CT = proplists:get_value("content-type", Headers, "application/octet-stream"),
    do_req({url(Path), Headers, CT, iolist_to_binary(Body)}, post).

do_req(Request) -> do_req(Request, get).
do_req(Request, Method) ->
    {ok, {{_, Code, _}, Headers, Body}} =
        httpc:request(Method, Request, [{autoredirect, false}], []),
    {Code, [{string:lowercase(K), V} || {K, V} <- Headers], Body}.

%% Extract "name=value" from a Set-Cookie header to send back as a Cookie.
cookie_kv(SetCookie) ->
    [KV | _] = string:split(SetCookie, ";"),
    KV.

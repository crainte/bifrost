%% EUnit tests for bifrost_auth: password hashing and signed session tokens.
%% These defend the actual security contract — a correct password must verify, a
%% wrong or tampered one must not, tokens must be unforgeable and expire — so a
%% regression in the crypto path fails here rather than in production.
-module(bifrost_auth_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SECRET, "0123456789abcdef0123456789abcdef").

%% ── Password hashing ──────────────────────────────────────────

%% A freshly hashed password verifies against its own hash.
hash_roundtrip_test() ->
    H = bifrost_auth:hash_password(<<"correct horse battery staple">>),
    ?assert(bifrost_auth:verify_password(<<"correct horse battery staple">>, H)).

%% The wrong password does not verify.
wrong_password_rejected_test() ->
    H = bifrost_auth:hash_password(<<"s3cret">>),
    ?assertNot(bifrost_auth:verify_password(<<"S3cret">>, H)),
    ?assertNot(bifrost_auth:verify_password(<<"">>, H)),
    ?assertNot(bifrost_auth:verify_password(<<"s3cret ">>, H)).

%% Each hash uses a fresh random salt, so the same password hashes differently
%% every time — yet both verify. (Guards against a missing/static salt.)
hash_is_salted_test() ->
    H1 = bifrost_auth:hash_password(<<"same">>),
    H2 = bifrost_auth:hash_password(<<"same">>),
    ?assertNotEqual(H1, H2),
    ?assert(bifrost_auth:verify_password(<<"same">>, H1)),
    ?assert(bifrost_auth:verify_password(<<"same">>, H2)).

%% The stored format is the documented pbkdf2$sha256$iter$salt$hash.
hash_format_test() ->
    H = bifrost_auth:hash_password(<<"x">>),
    ?assertMatch([<<"pbkdf2">>, <<"sha256">>, _Iter, _Salt, _Hash],
                 binary:split(H, <<"$">>, [global])).

%% A malformed stored hash returns false, never crashes.
malformed_hash_rejected_test() ->
    ?assertNot(bifrost_auth:verify_password(<<"pw">>, <<"garbage">>)),
    ?assertNot(bifrost_auth:verify_password(<<"pw">>, <<"pbkdf2$sha256$bad">>)),
    ?assertNot(bifrost_auth:verify_password(<<"pw">>, <<"">>)).

%% ── Session tokens (need the session secret in env) ───────────

token_test_() ->
    {setup,
     fun() -> os:putenv("BIFROST_SESSION_SECRET", ?SECRET) end,
     fun(_) -> os:unsetenv("BIFROST_SESSION_SECRET") end,
     [
      fun valid_token_verifies/0,
      fun tampered_token_rejected/0,
      fun expired_token_rejected/0,
      fun malformed_token_rejected/0,
      fun token_bound_to_secret/0
     ]}.

%% A freshly minted token verifies and reports a future expiry.
valid_token_verifies() ->
    T = bifrost_auth:make_token(),
    ?assertMatch({ok, _Expiry}, bifrost_auth:verify_token(T)),
    {ok, Exp} = bifrost_auth:verify_token(T),
    ?assert(Exp > erlang:system_time(second)).

%% Flipping any byte of the signature invalidates the token.
tampered_token_rejected() ->
    T = bifrost_auth:make_token(),
    [Payload, Sig] = binary:split(T, <<".">>),
    Bad = <<Payload/binary, ".", (flip_first(Sig))/binary>>,
    ?assertEqual({error, bad_signature}, bifrost_auth:verify_token(Bad)),
    %% Editing the payload (extending expiry) also breaks the signature.
    Forged = <<"99999999999.", Sig/binary>>,
    ?assertEqual({error, bad_signature}, bifrost_auth:verify_token(Forged)).

%% A token whose expiry is in the past is refused even if correctly signed.
expired_token_rejected() ->
    Expired = bifrost_auth:make_token(-1),
    ?assertEqual({error, expired}, bifrost_auth:verify_token(Expired)).

%% Structurally invalid tokens are refused.
malformed_token_rejected() ->
    ?assertEqual({error, malformed}, bifrost_auth:verify_token(<<"no-dot">>)),
    ?assertEqual({error, malformed}, bifrost_auth:verify_token(<<"">>)).

%% A token minted under one secret does not verify under another — the signature
%% is bound to BIFROST_SESSION_SECRET.
token_bound_to_secret() ->
    T = bifrost_auth:make_token(),
    os:putenv("BIFROST_SESSION_SECRET", "a-completely-different-secret-value!!"),
    ?assertEqual({error, bad_signature}, bifrost_auth:verify_token(T)),
    os:putenv("BIFROST_SESSION_SECRET", ?SECRET).

%% ── Credentials + fail-closed config ──────────────────────────

credentials_test_() ->
    {setup,
     fun() ->
         os:putenv("BIFROST_SESSION_SECRET", ?SECRET),
         os:putenv("BIFROST_ADMIN_USER", "admin"),
         os:putenv("BIFROST_ADMIN_PASSWORD_HASH",
                   binary_to_list(bifrost_auth:hash_password(<<"hunter2">>)))
     end,
     fun(_) ->
         os:unsetenv("BIFROST_SESSION_SECRET"),
         os:unsetenv("BIFROST_ADMIN_USER"),
         os:unsetenv("BIFROST_ADMIN_PASSWORD_HASH")
     end,
     [
      ?_assert(bifrost_auth:configured()),
      ?_assert(bifrost_auth:check_credentials(<<"admin">>, <<"hunter2">>)),
      ?_assertNot(bifrost_auth:check_credentials(<<"admin">>, <<"wrong">>)),
      ?_assertNot(bifrost_auth:check_credentials(<<"root">>, <<"hunter2">>)),
      ?_assertNot(bifrost_auth:check_credentials(<<"">>, <<"">>))
     ]}.

%% A wrong USERNAME must cost the same PBKDF2 work as a wrong password, or the
%% response time tells an attacker which usernames exist.
wrong_user_costs_as_much_as_wrong_password_test_() ->
    {setup,
     fun() ->
         os:putenv("BIFROST_SESSION_SECRET", ?SECRET),
         os:putenv("BIFROST_ADMIN_USER", "admin"),
         os:putenv("BIFROST_ADMIN_PASSWORD_HASH",
                   binary_to_list(bifrost_auth:hash_password(<<"hunter2">>)))
     end,
     fun(_) ->
         [os:unsetenv(V) || V <- ["BIFROST_SESSION_SECRET", "BIFROST_ADMIN_USER",
                                  "BIFROST_ADMIN_PASSWORD_HASH"]]
     end,
     {timeout, 60, fun() ->
         Time = fun(U, P) ->
             lists:min([element(1, timer:tc(bifrost_auth, check_credentials, [U, P]))
                        || _ <- lists:seq(1, 3)])
         end,
         WrongPass = Time(<<"admin">>, <<"nope">>),
         WrongUser = Time(<<"mallory">>, <<"nope">>),
         ?assert(WrongUser > WrongPass div 2)
     end}}.

%% The k8s Secret template ships placeholders. A deploy that forgets to replace
%% them must fail closed, not run with a forgeable, publicly-known session key.
placeholder_or_short_session_secret_is_refused_test() ->
    os:putenv("BIFROST_ADMIN_USER", "admin"),
    os:putenv("BIFROST_ADMIN_PASSWORD_HASH",
              binary_to_list(bifrost_auth:hash_password(<<"x">>))),
    try
        os:putenv("BIFROST_SESSION_SECRET", "CHANGE_ME_openssl_rand_hex_32"),
        ?assertNot(bifrost_auth:configured()),
        os:putenv("BIFROST_SESSION_SECRET", "0123456789abcdef0123456789abcde"),
        ?assertNot(bifrost_auth:configured()),
        os:putenv("BIFROST_SESSION_SECRET", ?SECRET),
        ?assert(bifrost_auth:configured())
    after
        [os:unsetenv(V) || V <- ["BIFROST_SESSION_SECRET", "BIFROST_ADMIN_USER",
                                 "BIFROST_ADMIN_PASSWORD_HASH"]]
    end.

strong_secret_test() ->
    ?assertNot(bifrost_auth:strong_secret(<<"bifrost">>)),
    ?assertNot(bifrost_auth:strong_secret(<<"CHANGE_ME_openssl_rand_hex_32_padding_xx">>)),
    ?assertNot(bifrost_auth:strong_secret(<<"change_me_and_some_more_padding_to_32_bytes">>)),
    ?assertNot(bifrost_auth:strong_secret(<<"short">>)),
    ?assert(bifrost_auth:strong_secret(<<"7f3c9a1e5b2d8f4a6c0e9b7d3f1a5c8e2b4d6f8a0c2e4b6d">>)).

%% A cluster with a weak/placeholder Erlang cookie is remote code execution for
%% anyone who can reach epmd/the distribution port, so a clustered node must
%% refuse to start with one. Single-node dev keeps working.
cluster_cookie_check_test() ->
    ?assertEqual(ok, bifrost_app:check_cookie(false, bifrost)),
    ?assertEqual({error, weak_cluster_cookie}, bifrost_app:check_cookie(true, bifrost)),
    ?assertEqual({error, weak_cluster_cookie},
                 bifrost_app:check_cookie(true, 'CHANGE_ME_openssl_rand_hex_32')),
    ?assertEqual(ok, bifrost_app:check_cookie(true, '7f3c9a1e5b2d8f4a6c0e9b7d3f1a5c8e2b4d6f8a')).

%% With no admin/secret env set, configured/0 is false so the middleware fails
%% closed (refuses traffic) instead of serving the app unauthenticated.
not_configured_fails_closed_test() ->
    os:unsetenv("BIFROST_ADMIN_USER"),
    os:unsetenv("BIFROST_ADMIN_PASSWORD_HASH"),
    os:unsetenv("BIFROST_SESSION_SECRET"),
    ?assertNot(bifrost_auth:configured()).

%% ── helpers ───────────────────────────────────────────────────

flip_first(<<C, Rest/binary>>) ->
    Flipped = case C of $A -> $B; _ -> $A end,
    <<Flipped, Rest/binary>>;
flip_first(<<>>) -> <<"X">>.

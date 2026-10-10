%% Authentication primitives for the web UI/API: password hashing (PBKDF2-HMAC-
%% SHA256) and signed, expiring session tokens (HMAC-SHA256). No external deps —
%% all crypto is from OTP's `crypto`.
%%
%% Secrets come from the environment (injected from a k8s Secret in production):
%%   BIFROST_ADMIN_USER           login name
%%   BIFROST_ADMIN_PASSWORD_HASH  output of hash_password/1
%%   BIFROST_SESSION_SECRET       HMAC key for session cookies (>= 16 bytes)
%%
%% Hash format (self-describing, so iteration count can change without breaking
%% existing hashes):  pbkdf2$sha256$<iterations>$<salt_b64>$<hash_b64>
-module(bifrost_auth).

-export([hash_password/1, verify_password/2,
         make_token/0, make_token/1, verify_token/1,
         admin_user/0, admin_hash/0, configured/0,
         check_credentials/2, session_ttl/0, strong_secret/1]).

-define(ITERATIONS, 210000).   %% OWASP 2023 floor for PBKDF2-HMAC-SHA256
-define(SALT_BYTES, 16).
-define(DKLEN, 32).
-define(SESSION_TTL, 43200).   %% 12 hours, seconds

%% ── Password hashing ──────────────────────────────────────────

-spec hash_password(binary()) -> binary().
hash_password(Password) when is_binary(Password) ->
    Salt = crypto:strong_rand_bytes(?SALT_BYTES),
    Hash = crypto:pbkdf2_hmac(sha256, Password, Salt, ?ITERATIONS, ?DKLEN),
    iolist_to_binary([
        <<"pbkdf2$sha256$">>, integer_to_binary(?ITERATIONS), <<"$">>,
        base64:encode(Salt), <<"$">>, base64:encode(Hash)
    ]).

%% Constant-time verification. Returns false on any malformed stored hash rather
%% than crashing (a bad secret must not 500 the login path).
-spec verify_password(binary(), binary()) -> boolean().
verify_password(Password, Stored) when is_binary(Password), is_binary(Stored) ->
    case binary:split(Stored, <<"$">>, [global]) of
        [<<"pbkdf2">>, <<"sha256">>, IterB, SaltB64, HashB64] ->
            try
                Iter = binary_to_integer(IterB),
                Salt = base64:decode(SaltB64),
                Expected = base64:decode(HashB64),
                Actual = crypto:pbkdf2_hmac(sha256, Password, Salt, Iter, byte_size(Expected)),
                constant_eq(Actual, Expected)
            catch _:_ -> false
            end;
        _ -> false
    end;
verify_password(_, _) -> false.

%% ── Session tokens ────────────────────────────────────────────
%% Token = <expiry_unix>.<hmac_b64url>, signed with BIFROST_SESSION_SECRET.
%% Stateless: no server-side session store. Rotating the secret invalidates all.

-spec make_token() -> binary().
make_token() -> make_token(session_ttl()).

-spec make_token(non_neg_integer()) -> binary().
make_token(TtlSeconds) ->
    Expiry = erlang:system_time(second) + TtlSeconds,
    Payload = integer_to_binary(Expiry),
    Sig = sign(Payload),
    <<Payload/binary, ".", Sig/binary>>.

%% Returns {ok, ExpiryUnix} for a valid, unexpired, correctly-signed token,
%% else {error, Reason}. Signature checked in constant time; expiry checked after.
-spec verify_token(binary()) -> {ok, integer()} | {error, atom()}.
verify_token(Token) when is_binary(Token) ->
    case binary:split(Token, <<".">>) of
        [Payload, Sig] ->
            Expected = sign(Payload),
            case constant_eq(Sig, Expected) of
                true ->
                    try
                        Expiry = binary_to_integer(Payload),
                        case erlang:system_time(second) < Expiry of
                            true -> {ok, Expiry};
                            false -> {error, expired}
                        end
                    catch _:_ -> {error, malformed} end;
                false -> {error, bad_signature}
            end;
        _ -> {error, malformed}
    end;
verify_token(_) -> {error, malformed}.

sign(Payload) ->
    base64url(crypto:mac(hmac, sha256, session_secret(), Payload)).

%% ── Credential check ──────────────────────────────────────────
%% True iff user matches the configured admin AND password verifies. The
%% password is verified even when the username is wrong: short-circuiting skipped
%% the ~100ms PBKDF2 for unknown users, so response time revealed which usernames
%% exist.
-spec check_credentials(binary(), binary()) -> boolean().
check_credentials(User, Password) when is_binary(User), is_binary(Password) ->
    UserOk = constant_eq(User, admin_user()),
    PassOk = verify_password(Password, admin_hash()),
    UserOk andalso PassOk;
check_credentials(_, _) -> false.

%% Auth is only enforced when fully configured; a half-configured deploy must
%% fail closed at the middleware, which calls configured/0.
-spec configured() -> boolean().
configured() ->
    admin_user() =/= <<>> andalso admin_hash() =/= <<>> andalso
        strong_secret(session_secret()).

%% At least 32 bytes and not a template placeholder. The shipped k8s Secret
%% template's "CHANGE_ME_openssl_rand_hex_32" is 29 bytes and passed the old
%% >=16 check, so an unedited deploy ran with a publicly known signing key and
%% anyone could forge an admin session. Also used for the Erlang cookie.
-spec strong_secret(binary()) -> boolean().
strong_secret(Secret) when is_binary(Secret) ->
    byte_size(Secret) >= 32
        andalso binary:match(string:lowercase(Secret), <<"change_me">>) =:= nomatch;
strong_secret(_) ->
    false.

%% ── Config accessors (env) ────────────────────────────────────

admin_user() -> env_bin("BIFROST_ADMIN_USER").
admin_hash() -> env_bin("BIFROST_ADMIN_PASSWORD_HASH").
session_secret() -> env_bin("BIFROST_SESSION_SECRET").
session_ttl() -> ?SESSION_TTL.

env_bin(Var) ->
    case os:getenv(Var) of
        false -> <<>>;
        "" -> <<>>;
        V -> list_to_binary(V)
    end.

%% ── Helpers ───────────────────────────────────────────────────

%% Constant-time equality — compares every byte regardless of mismatch position
%% so an attacker cannot use response timing to recover the secret byte by byte.
constant_eq(A, B) when is_binary(A), is_binary(B) ->
    case byte_size(A) =:= byte_size(B) of
        false -> false;
        true -> crypto:hash_equals(A, B)
    end;
constant_eq(_, _) -> false.

base64url(Bin) ->
    B = base64:encode(Bin),
    << <<(url_char(C))>> || <<C>> <= B, C =/= $= >>.

url_char($+) -> $-;
url_char($/) -> $_;
url_char(C) -> C.

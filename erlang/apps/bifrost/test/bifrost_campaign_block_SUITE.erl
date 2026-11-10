%% Explicit campaign blocking (threat-campaign-blocking) over REAL HTTP through
%% the production router + handler, against a REAL Postgres scratch database.
%%
%% What this pins:
%%  - activation is idempotent and revocable, with one monotonic policy revision
%%    bumped by the same statement as the write (the total order Rust rejects
%%    stale pushes by);
%%  - Block is policy, Dismiss is review: neither creates the other's state;
%%  - stale / unconfirmed / mismatched requests install nothing, and a failed
%%    write is an error, never an "active" rule;
%%  - the SQL matcher that decides campaign MEMBERSHIP agrees with the vectors
%%    Rust's DNS matcher is tested against (erlang/.../campaign_vectors.json).
%%
%% Distribution to other nodes is bifrost_cluster_SUITE; hydration and the
%% Postgres-outage behaviour is bifrost_db_resilience_SUITE.
-module(bifrost_campaign_block_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([activation_is_idempotent/1,
         unique_identity_is_enforced_by_the_database/1,
         block_creates_policy_not_a_suppression/1,
         dismiss_stays_review_only/1,
         invalid_stale_and_unconfirmed_requests_install_nothing/1,
         client_scope_is_part_of_the_identity/1,
         revoke_leaves_other_state_alone/1,
         revocation_stays_visible_until_confirmed/1,
         failed_snapshot_publication_retries_same_revision/1,
         revoke_distribution_failure_is_saved_and_visible/1,
         connected_old_resolver_cannot_admit_new_block/1,
         revisions_are_monotonic_and_read_is_one_snapshot/1,
         failed_write_is_an_error_not_an_active_rule/1,
         sql_matcher_agrees_with_the_shared_vectors/1]).

-define(PORT, 18125).

suite() -> [{timetrap, {seconds, 120}}].

all() ->
    [activation_is_idempotent,
     unique_identity_is_enforced_by_the_database,
     block_creates_policy_not_a_suppression,
     dismiss_stays_review_only,
     invalid_stale_and_unconfirmed_requests_install_nothing,
     client_scope_is_part_of_the_identity,
     revoke_leaves_other_state_alone,
     revocation_stays_visible_until_confirmed,
     failed_snapshot_publication_retries_same_revision,
     revoke_distribution_failure_is_saved_and_visible,
     connected_old_resolver_cannot_admit_new_block,
     revisions_are_monotonic_and_read_is_one_snapshot,
     failed_write_is_an_error_not_an_active_rule,
     sql_matcher_agrees_with_the_shared_vectors].

init_per_suite(Config) ->
    [{ok, _} = application:ensure_all_started(A) || A <- [crypto, epgsql, cowboy, inets]],
    Db = #{host => getenv("BIFROST_TEST_DB_HOST", "postgres"),
           port => list_to_integer(getenv("BIFROST_TEST_DB_PORT", "5432")),
           name => getenv("BIFROST_TEST_DB_NAME", "bifrost"),
           user => getenv("BIFROST_TEST_DB_USER", "bifrost"),
           pass => getenv("BIFROST_TEST_DB_PASSWORD", "bifrost")},
    Scratch = "bifrost_ct_campaign_" ++ integer_to_list(erlang:system_time(millisecond)),
    Admin = raw_connect(Db, maps:get(name, Db)),
    {ok, _, _} = epgsql:squery(Admin, "CREATE DATABASE " ++ Scratch),
    ok = epgsql:close(Admin),
    CfgPath = filename:join(?config(priv_dir, Config), "campaign_config.yaml"),
    ok = file:write_file(CfgPath, io_lib:format(
        "{database, [{host, ~p}, {port, ~p}, {name, ~p}, {user, ~p}]}.~n"
        "{upstreams, [[{address, \"192.0.2.53\"}, {port, 53}]]}.~n",
        [maps:get(host, Db), maps:get(port, Db), Scratch, maps:get(user, Db)])),
    os:putenv("BIFROST_CONFIG_PATH", CfgPath),
    os:putenv("BIFROST_DB_PASSWORD", maps:get(pass, Db)),
    os:unsetenv("BIFROST_CLUSTER_NODES"),
    os:unsetenv("BIFROST_CLUSTER_SERVICE"),
    application:set_env(mnesia, dir, filename:join(?config(priv_dir, Config), "mnesia")),
    ok = bifrost_mnesia:init_tables(),
    {ok, CfgPid} = bifrost_config_server:start_link(),
    unlink(CfgPid),
    {ok, PoolPid} = bifrost_db_pool:start_link(),
    unlink(PoolPid),
    ok = wait_connected(50),
    {ok, PolicyPid} = bifrost_campaign_policy:start_link(),
    unlink(PolicyPid),
    Dispatch = cowboy_router:compile(bifrost_router:routes()),
    {ok, _} = cowboy:start_clear(campaign_ct_listener, [{port, ?PORT}],
                                 #{env => #{dispatch => Dispatch}}),
    [{db, Db}, {scratch, Scratch} | Config].

end_per_suite(Config) ->
    cowboy:stop_listener(campaign_ct_listener),
    stop(bifrost_campaign_policy),
    stop(bifrost_db_pool),
    stop(bifrost_config_server),
    mnesia:stop(),
    Db = ?config(db, Config),
    Admin = raw_connect(Db, maps:get(name, Db)),
    epgsql:squery(Admin, "DROP DATABASE IF EXISTS " ++ ?config(scratch, Config) ++ " WITH (FORCE)"),
    epgsql:close(Admin),
    os:unsetenv("BIFROST_DB_PASSWORD"),
    os:unsetenv("BIFROST_CONFIG_PATH"),
    ok.

%% campaign_blocks is deliberately NOT cleared between cases: the policy server
%% tracks the revision, so tests assert on deltas and use their own parents.
init_per_testcase(_TC, Config) ->
    sql(Config, "CREATE TABLE IF NOT EXISTS query_log_campaign_test PARTITION OF query_log DEFAULT"),
    [sql(Config, "DELETE FROM " ++ T)
     || T <- ["manual_blocks", "allowlist", "suspicious_candidates", "threat_suppressions",
              "query_log"]],
    Config.

%% ── cases ─────────────────────────────────────────────────────

%% "When the same campaign/scope is activated twice, only one active rule exists
%% and the operator sees the existing rule."
activation_is_idempotent(Config) ->
    seed_family(Config, "idem.example.com", "10.1.1.1"),
    R0 = policy_revision(),
    {200, #{<<"created">> := true, <<"id">> := Id}} =
        post_json("/api/threats/campaigns/block", family_block("idem.example.com", null)),
    R1 = policy_revision(),
    ?assertEqual(R0 + 1, R1),
    {200, #{<<"created">> := false, <<"id">> := Id}} =
        post_json("/api/threats/campaigns/block", family_block("idem.example.com", null)),
    %% An existing rule must not bump the revision.
    ?assertEqual(R1, policy_revision()),
    ?assertEqual(1, count(Config, "SELECT count(*) FROM campaign_blocks "
                                  "WHERE parent = 'idem.example.com' AND revoked_at IS NULL")).

%% The partial unique index, not application code, is the final guard (two
%% operators clicking at once). A revoked row frees the identity again.
unique_identity_is_enforced_by_the_database(Config) ->
    Insert = "INSERT INTO campaign_blocks (kind, parent, tld, client_scope, revision) "
             "VALUES ('family', 'uniq.example.com', 'com', '', 1)",
    sql(Config, Insert),
    {error, Violation} = sql_result(Config, Insert),
    %% epgsql's #error{}: element 4 is the codename.
    ?assertEqual(unique_violation, element(4, Violation)),
    sql(Config, "UPDATE campaign_blocks SET revoked_at = now(), revoked_revision = 2 "
                "WHERE parent = 'uniq.example.com'"),
    sql(Config, Insert).

%% "...a review suppression is not created", candidates are untouched, and the
%% rule is listed separately with an honest, not-yet-applied state.
block_creates_policy_not_a_suppression(Config) ->
    seed_family(Config, "pol.example.com", "10.1.1.1"),
    {200, #{<<"state">> := State, <<"distribution">> := Dist, <<"pattern">> := Pattern}} =
        post_json("/api/threats/campaigns/block", family_block("pol.example.com", null)),
    ?assertEqual(<<"{n}.pol.example.com">>, Pattern),
    %% No Rust is connected in this test: a saved rule must NOT read as enforced.
    ?assertEqual(<<"applying">>, State),
    ?assert(lists:member(Dist, [<<"published">>, <<"saved_not_distributed">>])),
    ?assertEqual(0, count(Config, "SELECT count(*) FROM threat_suppressions")),
    ?assertEqual(4, count(Config, "SELECT count(*) FROM suspicious_candidates "
                                  "WHERE status = 'pending'")),
    {200, #{<<"blocks">> := Blocks, <<"blocks_available">> := true,
            <<"suppressions">> := [], <<"campaigns">> := [Campaign]}} =
        get_json("/api/threats/campaigns"),
    ?assert(lists:any(fun(#{<<"pattern">> := P}) -> P =:= Pattern end, Blocks)),
    ?assertMatch([#{<<"state">> := <<"applying">>}], maps:get(<<"blocked_by">>, Campaign)).

%% "Dismiss remains review-only": DNS policy and its revision do not move.
dismiss_stays_review_only(Config) ->
    seed_family(Config, "dis.example.com", "10.1.1.1"),
    R0 = policy_revision(),
    Rules0 = count(Config, "SELECT count(*) FROM campaign_blocks"),
    {200, #{<<"dismissed">> := 4}} =
        post_json("/api/threats/campaigns/dismiss",
                  #{<<"kind">> => <<"family">>, <<"parent">> => <<"dis.example.com">>}),
    ?assertEqual(R0, policy_revision()),
    ?assertEqual(Rules0, count(Config, "SELECT count(*) FROM campaign_blocks")),
    ?assertEqual(1, count(Config, "SELECT count(*) FROM threat_suppressions")).

%% "A pattern that is invalid, does not match the claimed campaign shape, or is
%% no longer available is rejected and no rule is installed."
invalid_stale_and_unconfirmed_requests_install_nothing(Config) ->
    seed_family(Config, "bad.example.com", "10.1.1.1"),
    Rules0 = count(Config, "SELECT count(*) FROM campaign_blocks"),
    R0 = policy_revision(),
    Good = family_block("bad.example.com", null),
    Bad = [maps:remove(<<"confirm">>, Good),
           Good#{<<"confirm">> => false},
           Good#{<<"pattern">> => <<"{n}.something.else">>},
           Good#{<<"tld">> => <<"net">>},
           Good#{<<"leading_label">> => <<"447">>},
           Good#{<<"parent">> => <<"gone.example.com">>, <<"pattern">> => <<"{n}.gone.example.com">>},
           Good#{<<"kind">> => <<"regex">>},
           Good#{<<"client_ip">> => <<"nope">>},
           %% valid IP, but that client never queried the campaign
           Good#{<<"client_ip">> => <<"10.9.9.9">>},
           #{<<"confirm">> => true}],
    [?assertMatch({400, #{<<"error">> := _}}, post_json("/api/threats/campaigns/block", B))
     || B <- Bad],
    ?assertMatch({400, _}, post_raw("/api/threats/campaigns/block", <<"not json">>)),
    ?assertEqual(Rules0, count(Config, "SELECT count(*) FROM campaign_blocks")),
    ?assertEqual(R0, policy_revision()).

client_scope_is_part_of_the_identity(Config) ->
    seed_family(Config, "scope.example.com", "10.1.1.1"),
    {200, #{<<"id">> := All, <<"client_ip">> := null}} =
        post_json("/api/threats/campaigns/block", family_block("scope.example.com", null)),
    {200, #{<<"id">> := One, <<"client_ip">> := <<"10.1.1.1">>, <<"created">> := true}} =
        post_json("/api/threats/campaigns/block",
                  family_block("scope.example.com", <<"10.1.1.1">>)),
    ?assertNotEqual(All, One),
    {200, #{<<"id">> := One, <<"created">> := false}} =
        post_json("/api/threats/campaigns/block",
                  family_block("scope.example.com", <<"10.1.1.1">>)),
    {ok, #{rules := Rules}} = bifrost_campaign_block_store:read(),
    Scoped = [R || #{id := I} = R <- Rules, I =:= One],
    ?assertMatch([#{client_ip := <<"10.1.1.1">>, kind := <<"family">>,
                    parent := <<"scope.example.com">>}], Scoped).

%% "Revoke: the rule stops ...; review suppression state is unchanged", and
%% exact-domain blocks are not touched.
revoke_leaves_other_state_alone(Config) ->
    seed_family(Config, "rev.example.com", "10.1.1.1"),
    sql(Config, "INSERT INTO manual_blocks (domain) VALUES ('3.rev.example.com')"),
    sql(Config, "INSERT INTO threat_suppressions (kind, tld, leading_label, parent, expires_at) "
                "VALUES ('family', 'com', NULL, 'other.example.com', now() + interval '1 day')"),
    {200, #{<<"id">> := Id}} =
        post_json("/api/threats/campaigns/block", family_block("rev.example.com", null)),
    R1 = policy_revision(),
    {202, #{<<"state">> := <<"revoking">>}} = post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => Id}),
    ?assert(policy_revision() > R1),
    {ok, #{rules := Rules}} = bifrost_campaign_block_store:read(),
    ?assertNot(lists:any(fun(#{id := I}) -> I =:= Id end, Rules)),
    ?assertEqual(1, count(Config, "SELECT count(*) FROM manual_blocks")),
    ?assertEqual(1, count(Config, "SELECT count(*) FROM threat_suppressions "
                                  "WHERE revoked_at IS NULL")),
    ?assertEqual(4, count(Config, "SELECT count(*) FROM suspicious_candidates "
                                  "WHERE status = 'pending'")),
    %% A repeated revoke is idempotent; unknown id and junk are not found.
    ?assertMatch({202, #{<<"state">> := <<"revoking">>}},
                 post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => Id})),
    ?assertMatch({404, _}, post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => 999999999})),
    ?assertMatch({404, _}, post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => <<"x">>})),
    %% The identity is free again: re-activation creates a NEW row.
    {200, #{<<"id">> := New, <<"created">> := true}} =
        post_json("/api/threats/campaigns/block", family_block("rev.example.com", null)),
    ?assertNotEqual(Id, New).

revocation_stays_visible_until_confirmed(Config) ->
    seed_family(Config, "visible.example.com", "10.1.1.1"),
    {200, #{<<"id">> := Id}} = post_json("/api/threats/campaigns/block", family_block("visible.example.com", null)),
    {202, #{<<"state">> := <<"revoking">>}} =
        post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => Id}),
    {200, #{<<"blocks">> := Blocks}} = get_json("/api/threats/campaigns"),
    ?assertMatch([#{<<"state">> := <<"revoking">>}],
        [B || #{<<"id">> := I} = B <- Blocks, I =:= Id]),
    %% Retrying a persisted revoke must not bump the revision again.
    Revision = policy_revision(),
    {202, #{<<"state">> := <<"revoking">>}} =
        post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => Id}),
    ?assertEqual(Revision, policy_revision()).

%% Revisions only go up (revoke included), and read/0 reports a revision together
%% with exactly the rules that revision contains.
revisions_are_monotonic_and_read_is_one_snapshot(Config) ->
    seed_family(Config, "mono.example.com", "10.1.1.1"),
    {ok, #{revision := R0}} = bifrost_campaign_block_store:read(),
    {created, #{id := Id, revision := RuleRev}} = bifrost_campaign_block_store:activate(
        #{kind => family, parent => <<"mono.example.com">>, leading_label => null,
          tld => <<"com">>, client_ip => null, observed_domains => 4}),
    {ok, #{revision := R1, rules := Rules1}} = bifrost_campaign_block_store:read(),
    ?assertEqual(R0 + 1, R1),
    ?assertEqual(R1, RuleRev),
    ?assert(lists:any(fun(#{id := I}) -> I =:= Id end, Rules1)),
    {ok, _} = bifrost_campaign_block_store:revoke(Id),
    {ok, #{revision := R2, rules := Rules2}} = bifrost_campaign_block_store:read(),
    ?assertEqual(R1 + 1, R2),
    ?assertNot(lists:any(fun(#{id := I}) -> I =:= Id end, Rules2)),
    ?assertMatch({ok, #{revoked_revision := R2}}, bifrost_campaign_block_store:revoke(Id)),
    {ok, #{revision := R3}} = bifrost_campaign_block_store:read(),
    %% A failed revoke must not bump the revision.
    ?assertEqual(R2, R3).

failed_snapshot_publication_retries_same_revision(_Config) ->
    ok = bifrost_campaign_policy:refresh(),
    #{desired_revision := Before} = bifrost_campaign_policy:status(),
    {created, _} = bifrost_campaign_block_store:activate(
        #{kind => family, parent => <<"retry.example.com">>, leading_label => null,
          tld => <<"com">>, client_ip => null, observed_domains => 4}),
    {ok, #{revision := Revision} = Snapshot} = bifrost_campaign_block_store:read(),
    {atomic, ok} = mnesia:change_table_access_mode(opconfig, read_only),
    try
        ?assertMatch({error, {publication_failed, _}}, bifrost_campaign_policy:refresh()),
        ?assertEqual(Before, maps:get(desired_revision, bifrost_campaign_policy:status()))
    after
        {atomic, ok} = mnesia:change_table_access_mode(opconfig, read_write)
    end,
    ok = bifrost_campaign_policy:refresh(),
    ?assertEqual(Revision, maps:get(desired_revision, bifrost_campaign_policy:status())),
    ?assertEqual({ok, Snapshot}, bifrost_opconfig:snapshot(campaign_blocks)),
    %% Even an unchanged desired revision must restore a lost durable snapshot.
    ok = mnesia:dirty_delete(opconfig, campaign_blocks),
    ok = bifrost_campaign_policy:refresh(),
    ?assertEqual({ok, Snapshot}, bifrost_opconfig:snapshot(campaign_blocks)).

revoke_distribution_failure_is_saved_and_visible(Config) ->
    seed_family(Config, "outage.example.com", "10.1.1.1"),
    {200, #{<<"id">> := Id}} =
        post_json("/api/threats/campaigns/block", family_block("outage.example.com", null)),
    {atomic, ok} = mnesia:change_table_access_mode(opconfig, read_only),
    try
        {503, #{<<"saved">> := true, <<"distribution">> := <<"saved_not_distributed">>}} =
            post_json("/api/threats/campaign-blocks/revoke", #{<<"id">> => Id}),
        ?assertEqual(1, count(Config, "SELECT count(*) FROM campaign_blocks WHERE id = " ++
                                      integer_to_list(Id) ++ " AND revoked_at IS NOT NULL")),
        {200, #{<<"blocks">> := Blocks}} = get_json("/api/threats/campaigns"),
        ?assertMatch([#{<<"state">> := <<"revoke_failed">>}],
                     [B || #{<<"id">> := I} = B <- Blocks, I =:= Id])
    after
        {atomic, ok} = mnesia:change_table_access_mode(opconfig, read_write)
    end,
    ok = bifrost_campaign_policy:refresh().

connected_old_resolver_cannot_admit_new_block(Config) ->
    seed_family(Config, "legacy.example.com", "10.1.1.1"),
    Fake = spawn(fun Old() ->
        receive
            {'$gen_call', From, connection_id} ->
                gen_server:reply(From, old_connection), Old();
            {'$gen_call', From, _} ->
                gen_server:reply(From, ok), Old()
        end
    end),
    true = register(bifrost_socket_server, Fake),
    try
        {503, #{<<"error">> := _}} =
            post_json("/api/threats/campaigns/block", family_block("legacy.example.com", null)),
        ?assertEqual(0, count(Config,
            "SELECT count(*) FROM campaign_blocks WHERE parent = 'legacy.example.com'"))
    after
        unregister(bifrost_socket_server),
        exit(Fake, kill)
    end.

%% "A failed persistence ... step SHALL not be reported as a successful
%% activation." Break the table; the API must say so and nothing must be active.
failed_write_is_an_error_not_an_active_rule(Config) ->
    seed_family(Config, "fail.example.com", "10.1.1.1"),
    sql(Config, "ALTER TABLE campaign_blocks RENAME TO campaign_blocks_broken"),
    try
        ?assertMatch({500, #{<<"error">> := _}},
                     post_json("/api/threats/campaigns/block", family_block("fail.example.com", null))),
        %% The page cannot know the rule state either, and must say so.
        {200, #{<<"blocks_available">> := false, <<"blocks">> := []}} =
            get_json("/api/threats/campaigns")
    after
        sql(Config, "ALTER TABLE campaign_blocks_broken RENAME TO campaign_blocks")
    end,
    ?assertEqual(0, count(Config, "SELECT count(*) FROM campaign_blocks "
                                  "WHERE parent = 'fail.example.com'")).

%% The SQL matcher decides which pending candidates belong to a campaign (and
%% what a dismissal hides); Rust's matcher decides DNS. Same vectors for both.
sql_matcher_agrees_with_the_shared_vectors(_Config) ->
    #{<<"cases">> := Cases} = vectors(),
    Expr = lists:flatten(bifrost_threat_campaigns:match_sql(
        "$1::text", "$2::text", "$3::text", "$4::text", "$5::text")),
    Sql = "SELECT COALESCE(" ++ Expr ++ ", false)",
    [begin
         #{<<"rule">> := Rule} = Case,
         Kind = maps:get(<<"kind">>, Rule),
         Parent = maps:get(<<"parent">>, Rule, null),
         Label = maps:get(<<"leading_label">>, Rule, null),
         Tld = maps:get(<<"tld">>, Rule),
         Matches = fun(Name) ->
             {ok, _, [{M}]} = bifrost_db_pool:equery(Sql, [normalise(Name), Kind, Tld, Label, Parent]),
             M
         end,
         [expect(true, Matches(N), {should_match, Rule, N}) || N <- maps:get(<<"match">>, Case)],
         [expect(false, Matches(N), {should_not_match, Rule, N}) || N <- maps:get(<<"no_match">>, Case)]
     end || Case <- Cases],
    ok.

%% ── helpers ───────────────────────────────────────────────────

expect(Expected, Expected, _Info) -> ok;
expect(_Expected, Actual, Info) -> ct:fail({Info, got, Actual}).

vectors() ->
    Path = filename:join(filename:dirname(?FILE), "campaign_vectors.json"),
    {ok, Bin} = file:read_file(Path),
    jsx:decode(Bin, [return_maps]).

%% The SQL side sees query_log names: lowercase, no terminal dot.
normalise(Name) ->
    string:trim(string:lowercase(Name), trailing, ".").

%% Four pending siblings (a family needs >= 3) that Client queried.
seed_family(Config, Parent, Client) ->
    Names = [integer_to_list(N) ++ "." ++ Parent || N <- lists:seq(0, 3)],
    [sql(Config, "INSERT INTO query_log (client_ip, domain, qtype, action, client_rcode) VALUES ('"
                 ++ Client ++ "', '" ++ D ++ "', 1, 'NOERROR', 'NOERROR')") || D <- Names],
    [sql(Config, "INSERT INTO suspicious_candidates (domain, score, hits) VALUES ('" ++ D ++ "', 4, 2)")
     || D <- Names],
    ok.

family_block(Parent, Client) ->
    P = list_to_binary(Parent),
    #{<<"kind">> => <<"family">>, <<"parent">> => P, <<"pattern">> => <<"{n}.", P/binary>>,
      <<"client_ip">> => Client, <<"confirm">> => true}.

policy_revision() ->
    {ok, #{revision := R}} = bifrost_campaign_block_store:read(),
    R.

count(Config, Sql) ->
    [{N}] = rows(Config, Sql),
    binary_to_integer(N).

get_json(Path) -> json_request(get, Path, none).
post_json(Path, Body) -> json_request(post, Path, Body).

post_raw(Path, Raw) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path,
    {ok, {{_, Code, _}, _, _}} =
        httpc:request(post, {Url, [], "application/json", Raw}, [{timeout, 10000}], []),
    {Code, #{}}.

json_request(Method, Path, Body) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(?PORT) ++ Path,
    Req = case Body of
        none -> {Url, []};
        _ -> {Url, [], "application/json", jsx:encode(Body)}
    end,
    {ok, {{_, Code, _}, _, Resp}} = httpc:request(Method, Req, [{timeout, 10000}], []),
    {Code, case Resp of [] -> #{}; _ -> jsx:decode(list_to_binary(Resp), [return_maps]) end}.

with_direct(Config, Fun) ->
    C = raw_connect(?config(db, Config), ?config(scratch, Config)),
    try Fun(C) after epgsql:close(C) end.

sql(Config, Sql) ->
    case sql_result(Config, Sql) of
        {ok, _} -> ok;
        {ok, _, _} -> ok;
        Err -> ct:fail({sql_failed, Sql, Err})
    end.

sql_result(Config, Sql) ->
    with_direct(Config, fun(C) -> epgsql:squery(C, Sql) end).

rows(Config, Sql) ->
    {ok, _, Rows} = with_direct(Config, fun(C) -> epgsql:squery(C, Sql) end),
    Rows.

raw_connect(Db, Name) ->
    {ok, C} = epgsql:connect(maps:get(host, Db), maps:get(user, Db), maps:get(pass, Db),
                             [{port, maps:get(port, Db)}, {database, Name}]),
    C.

wait_connected(0) -> {error, db_never_connected};
wait_connected(N) ->
    case catch bifrost_db_pool:query("SELECT 1 FROM campaign_blocks LIMIT 1") of
        {ok, _, _} -> ok;
        _ -> timer:sleep(200), wait_connected(N - 1)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            Ref = monitor(process, Pid),
            exit(Pid, shutdown),
            receive {'DOWN', Ref, process, Pid, _} -> ok
            after 5000 -> exit(Pid, kill)
            end
    end.

getenv(Var, Default) ->
    case os:getenv(Var) of false -> Default; "" -> Default; V -> V end.

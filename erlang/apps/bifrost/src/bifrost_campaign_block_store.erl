-module(bifrost_campaign_block_store).

%% Postgres side of explicit campaign blocks (migration 018). Postgres is the
%% source of truth; bifrost_campaign_policy publishes what is read here to every
%% node and to Rust. Every write bumps the single policy revision in the SAME
%% statement, so the revision is the total order Rust and peers use to reject
%% stale pushes.

-export([read/0, activate/1, revoke/1, active/0]).

-define(TIMEOUT, 3000).

-define(COLS, "id, kind, parent, leading_label, tld, host(client_ip), "
              "observed_domains, revision, "
              "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), revoked_revision").

%% The whole policy in one statement (one snapshot): its revision and every
%% active rule. Used for publication and Rust, so it carries no display fields.
-spec read() -> {ok, #{revision := non_neg_integer(), rules := [map()]}} | {error, term()}.
read() ->
    Sql = "SELECT p.revision, b.id, b.kind, b.parent, b.leading_label, b.tld, host(b.client_ip) "
          "FROM campaign_block_policy p "
          "LEFT JOIN campaign_blocks b ON b.revoked_at IS NULL "
          "WHERE p.singleton ORDER BY b.id",
    case bifrost_db_pool:equery(Sql, [], ?TIMEOUT) of
        {ok, _, [{Revision, _, _, _, _, _, _} | _] = Rows} ->
            {ok, #{revision => Revision,
                   rules => [wire_rule(R) || {_, Id, _, _, _, _, _} = R <- Rows, Id =/= null]}};
        {ok, _, []} -> {error, no_policy_row};
        {error, Reason} -> {error, Reason};
        Other -> {error, Other}
    end.

%% Include revocations until every resolver has acknowledged the removal.
-spec active() -> {ok, [map()]} | {error, term()}.
active() ->
    Sql = "SELECT " ?COLS " FROM campaign_blocks ORDER BY id",
    case bifrost_db_pool:equery(Sql, [], ?TIMEOUT) of
        {ok, _, Rows} -> {ok, [display_rule(R) || R <- Rows]};
        {error, Reason} -> {error, Reason};
        Other -> {error, Other}
    end.

%% Idempotent: an existing active rule for the same normalised identity is
%% returned as `{existing, Rule}` and does NOT bump the revision or add a row.
%% `Pattern` is a validated map (bifrost_threat_campaigns:validate_block/1).
-spec activate(map()) -> {created | existing, map()} | {error, term()}.
activate(#{kind := Kind, parent := Parent, leading_label := Label, tld := Tld,
           client_ip := Client, observed_domains := Observed}) ->
    Params = [atom_to_binary(Kind), Parent, Label, Tld, Client, Observed],
    Insert =
        "WITH existing AS (SELECT id FROM campaign_blocks WHERE revoked_at IS NULL "
        "    AND kind = $1::text AND parent = COALESCE($2::text, '') "
        "    AND leading_label = COALESCE($3::text, '') AND tld = $4::text "
        "    AND client_scope = COALESCE(host($5::inet), '')), "
        "bump AS (UPDATE campaign_block_policy SET revision = revision + 1 "
        "    WHERE singleton AND NOT EXISTS (SELECT 1 FROM existing) RETURNING revision), "
        "ins AS (INSERT INTO campaign_blocks "
        "    (kind, parent, leading_label, tld, client_ip, client_scope, observed_domains, revision) "
        "    SELECT $1::text, COALESCE($2::text, ''), COALESCE($3::text, ''), $4::text, $5::inet, "
        "           COALESCE(host($5::inet), ''), $6::int, bump.revision FROM bump "
        "    ON CONFLICT DO NOTHING RETURNING id) "
        "SELECT id FROM ins",
    Find =
        "SELECT " ?COLS " FROM campaign_blocks WHERE revoked_at IS NULL "
        "AND kind = $1::text AND parent = COALESCE($2::text, '') "
        "AND leading_label = COALESCE($3::text, '') AND tld = $4::text "
        "AND client_scope = COALESCE(host($5::inet), '')",
    case bifrost_db_pool:equery(Insert, Params, ?TIMEOUT) of
        {ok, _, Inserted} ->
            case bifrost_db_pool:equery(Find, lists:sublist(Params, 5), ?TIMEOUT) of
                {ok, _, [Row]} ->
                    {case Inserted of [] -> existing; _ -> created end, display_rule(Row)};
                {ok, _, []} -> {error, not_found_after_insert};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason};
        Other -> {error, Other}
    end.

%% Marks the rule revoked and bumps the revision atomically. Exact-domain
%% blocks and review suppressions are different tables and are not touched.
-spec revoke(integer()) -> {ok, map()} | {error, not_found | term()}.
revoke(Id) when is_integer(Id), Id > 0 ->
    Sql = "WITH target AS (SELECT id FROM campaign_blocks "
          "    WHERE id = $1::bigint AND revoked_at IS NULL FOR UPDATE), "
          "bump AS (UPDATE campaign_block_policy SET revision = revision + 1 "
          "    WHERE singleton AND EXISTS (SELECT 1 FROM target) RETURNING revision), "
          "rev AS (UPDATE campaign_blocks b SET revoked_at = now(), "
          "    revoked_revision = (SELECT revision FROM bump) "
          "    FROM target t WHERE b.id = t.id RETURNING b.id) "
          "SELECT id FROM rev",
    case bifrost_db_pool:equery(Sql, [Id], ?TIMEOUT) of
        {ok, _, _} ->
            case bifrost_db_pool:equery("SELECT " ?COLS " FROM campaign_blocks WHERE id = $1::bigint",
                                         [Id], ?TIMEOUT) of
                {ok, _, [Row]} -> {ok, display_rule(Row)};
                {ok, _, []} -> {error, not_found};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason};
        Other -> {error, Other}
    end;
revoke(_) -> {error, not_found}.

%% ── Row shapes ────────────────────────────────────────────────

%% What goes over IPC and into the replicated snapshot.
wire_rule({_Rev, Id, Kind, Parent, Label, Tld, Ip}) ->
    #{id => Id, kind => Kind, parent => blank_null(Parent), tld => Tld,
      leading_label => blank_null(Label), client_ip => Ip}.

display_rule({Id, Kind, Parent, Label, Tld, Ip, Observed, Revision, Created, RevokedRevision}) ->
    #{id => Id, kind => Kind, parent => blank_null(Parent), tld => Tld,
      leading_label => blank_null(Label), client_ip => Ip,
      observed_domains => Observed, revision => Revision, created_at => Created,
      revoked_revision => RevokedRevision,
      pattern => case Kind of
          <<"family">> -> <<"{n}.", Parent/binary>>;
          _ -> <<Label/binary, ".*.", Tld/binary>>
      end}.

blank_null(<<>>) -> null;
blank_null(V) -> V.

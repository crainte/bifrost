# Design

## Context

See proposal.md and the threat-campaign-blocking spec. `bifrost_threat_campaigns` currently groups pending candidates into family/marker patterns and uses `match_sql/5` only for review suppressions. Rust's blocklist and per-client block indexes are exact/suffix matchers, not arbitrary patterns. Postgres is operational config's source of truth; `bifrost_opconfig` snapshots successful reads in Mnesia for cold restarts during a DB outage. `bifrost_blocklist_manager` rehydrates Rust after reconnect, and cross-node config reloads already exist. Allowlist checks precede blocking in `listener.rs`.

## Goals / Non-Goals

**Goals:** A persistent, explicitly activated DNS rule for both campaign shapes, with a bounded hot-path matcher, same scope on every node, an honest activation status, and a reversible UI action.

**Non-Goals:** Turning review suppression into blocking, treating URLs/paths as DNS match targets, automatically blocking newly detected campaigns, or converting wildcard-looking patterns to parent-domain blocklist entries.

## Decisions

### Separate policy from candidate state

Add a dedicated `campaign_blocks` table with unique normalized `(kind, parent-or-label, tld, client scope)` identity, activation/revocation timestamps and an operator-visible status. Do not insert 82 observed names as manual blocks or mark candidate rows dismissed: that would neither cover future names nor preserve independent review semantics. Keep exact-domain manual blocks and review suppressions independent. Display active rules separately; show pending/failed application explicitly rather than presenting a DB write as fully enforced DNS policy.

### Reuse campaign identity, not free-form wildcard regex

The API accepts the same structured `kind/parent/tld/leading_label/client_ip` tuple returned for a currently eligible campaign, validates it server-side against a fresh campaign listing, and requires explicit confirmation with a sample count and broad marker warning. It does not accept an arbitrary user-supplied regex. Resolve conflicts/duplicate activation by a unique database constraint. Marker means exact first label, a TLD suffix and at least three labels; family means the existing enumerated first-label syntax with exactly the stored parent. Match normalized lowercase names with a stripped terminal dot and label boundaries. Add cross-language conformance tests sharing representative match/non-match vectors with the existing SQL suppression matcher.

### Rust owns DNS-time evaluation

Ship a dedicated `load_campaign_blocks` message containing the full current rule set (including optional client IP). Rust builds an indexed immutable set keyed by family parent or marker `(tld, first label)` and atomically replaces it; no regex scan over a large table per DNS query. Check after allowlist but before cache/forward, only when protection is enabled; include `campaign:<rule id>` attribution in query events. The controller pushes from Postgres with `bifrost_opconfig` snapshot fallback on reconnect, config broadcasts on changes, and heals/resyncs peers. Revoke replaces the full set and must not undo independent exact blocks.

### Honest activation semantics

An API write may persist before every Rust process receives a new configuration. Report `saved/applying` until the relevant resolver acknowledgement or verifiable applied revision is observed; if application fails, surface the failure and retry rather than claiming DNS protection. Follow the existing revision/acknowledgement pattern used for DNS settings where practical, but keep campaign rule versioning separate. Readiness must not be marked hydrated with a missing required campaign-policy snapshot if a rule set was previously active. On DB outage use the last-known Mnesia snapshot; if neither database nor snapshot can supply policy, fail closed for this policy rather than silently loading an empty rule set. A newly installed node must hydrate its rule set before it advertises readiness. Control-plane downtime cannot be allowed to poison the DNS hot path with a stale partial update.

## Risks / Trade-offs

- **Marker breadth:** `447.*.site` spans unrelated registrable domains → confirmation repeats exact reach, displays current distinct domains/count, and defaults to the row's explicit scope; no auto-block.
- **Divergent matchers:** SQL for candidate membership and Rust for DNS enforcement could disagree → shared edge-case vectors in both test suites, including Unicode/IDN normalization policy and label boundaries.
- **Propagation lag or partition:** a persisted rule is not yet enforced everywhere → applied-revision tracking/status and retry on reconnect/heal; never display a saved rule as already active without evidence.
- **Existing cache entries:** previously cached answers could bypass policy → Rust checks campaign policy before cache lookup; revoke leaves cache behavior governed by other rules.
- **Cluster snapshot staleness:** out-of-order refresh could overwrite a new rule set → monotonic revision/atomic replacement, tested across two nodes.

## Migration Plan

1. Add the table and indexes as a forward-only migration; existing suppressions and manual blocks remain unchanged.
2. Deploy readers and IPC support before exposing Block campaign; older nodes must not acknowledge a policy revision they cannot enforce. Initial empty policy hydrates normally.
3. Expose UI action and status only once the write/push path is in place; do not auto-create rules from existing campaigns.
4. Rollback removes the UI action and leaves stored rules inert only if the operator explicitly revokes them before returning to a build without enforcement. Preserve the table/data so a rolling restart does not silently erase operator intent.

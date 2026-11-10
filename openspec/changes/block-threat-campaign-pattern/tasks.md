# Tasks

## 1. Persistent campaign policy and API

- [ ] 1.1 Add a forward-only migration for normalized unique campaign-block identities, scope, revision and revocation; verify migrations and duplicate insert behavior against Postgres.
- [ ] 1.2 Implement server-side validation against current campaign patterns, create/list/revoke API, and application status without conflating dismiss/suppress; verify HTTP tests cover invalid/stale patterns, scope, duplicates and failed writes.

## 2. DNS enforcement and convergence

- [ ] 2.1 Add a dedicated Rust campaign matcher and test-first cases for family/marker boundaries, normalization, global/client scope and no query-history dependency; run `cargo test` and clippy.
- [ ] 2.2 Wire the matcher into the live DNS path after allowlist and before cache, with query attribution and pause precedence; verify UDP integration tests for unseen names, allowlisted names, two clients and revoke/reload.
- [ ] 2.3 Publish a revisioned full rule set via IPC, hydrate it from Postgres/snapshot and resync on cluster reload/heal; verify two-node, reconnect, DB-outage and stale-revision tests (mutation-check the distributed test by reintroducing the missing push).
- [ ] 2.4 Expose applied/pending/failed status and retry behavior without falsely claiming enforcement; verify tests for lost ACK, older node/version and a failed distribution.

## 3. Threats UI and operator controls

- [ ] 3.1 Add Block campaign next to Dismiss with an explicit confirmation for selected client/all-clients scope, observed count and future-name reach (especially broad markers); verify UI tests and review the text against the spec.
- [ ] 3.2 Show active/pending campaign blocks with attribution and revoke controls separate from suppressions; update Threats/Rules operator copy and verify the UI and API tests, including that dismiss remains review-only.

## 4. Integration gate

- [ ] 4.1 Run `openspec validate block-threat-campaign-pattern --strict --no-interactive`, Rust fmt/clippy/tests, Erlang EUnit/Common Test and CI; verify a fresh PR-head check list is green and record any unavailable local gates.

## Workflow follow-up

- Merge only after human review; archive the OpenSpec change after the implementation is accepted.

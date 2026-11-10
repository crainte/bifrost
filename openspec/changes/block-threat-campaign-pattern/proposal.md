# Proposal

## Why

The Threats page groups related DNS hostnames into campaigns, but its only campaign action is **Dismiss**, which suppresses review and never changes DNS. Blocking today's individual candidates does not protect against matching hostnames first queried tomorrow. Operators need an explicit, reversible campaign-wide DNS block, distinct from hiding an alert.

## What Changes

- Add a **Block campaign** action for family (`{n}.parent.example`) and marker (`447.*.site`) patterns, with explicit client/all-clients scope, a preview of the matched pattern and current candidates, and confirmation of its DNS impact.
- Persist and distribute campaign rules as live DNS policy to every resolver. Match newly queried hostnames as well as the known members; preserve the existing allowlist override and protection-pause behavior.
- Show active campaign blocks separately from review suppressions, with scope and revoke controls. Keep **Dismiss** as a review-only action, with wording that does not imply DNS blocking.
- Exercise pattern boundaries, propagation/restart, scope, revocation, and DNS responses with regression tests.

## Capabilities

### New Capabilities
- `threat-campaign-blocking`: Explicitly manage and enforce DNS block rules derived from threat campaign patterns.

### Modified Capabilities
None; this repository has no existing OpenSpec baseline specs.

## Impact

Threats UI/API, campaign validation, PostgreSQL migrations/snapshotting, Erlang→Rust IPC/hydration and cluster propagation, Rust DNS hot path and query attribution, tests and operator documentation. No change to the existing review-only suppression semantics.

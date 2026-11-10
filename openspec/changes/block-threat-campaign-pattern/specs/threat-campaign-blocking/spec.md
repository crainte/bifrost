# Spec Delta

## Purpose

Enables operators to explicitly block a threat campaign's DNS hostname pattern, including matching names that have not yet appeared in traffic, without confusing DNS policy with review suppression.

## ADDED Requirements

### Requirement: Explicit campaign action
The Threats UI SHALL offer a separate Block campaign action for family and marker campaigns, without changing the review-only Dismiss action. Blocking SHALL require explicit confirmation showing pattern, scope, and that future matching hostnames will be denied at DNS resolution.

#### Scenario: Block a family
- **WHEN** an operator confirms blocking `{n}.stg.example.com` for all clients
- **THEN** the UI shows an active DNS block rule and does not create a review suppression

#### Scenario: Broad marker warning
- **WHEN** an operator chooses to block `447.*.site`
- **THEN** confirmation states that the rule reaches matching hostnames under other registrable `.site` domains, including names not in today's list

#### Scenario: Dismiss remains review-only
- **WHEN** an operator dismisses a campaign
- **THEN** its matching candidates are hidden from review until suppression expiry, but DNS behavior is unchanged

### Requirement: Pattern-exact DNS enforcement
An active campaign block SHALL match the same family or marker shape displayed in the campaign and SHALL apply to new as well as previously queried hostnames. Matching SHALL be case-insensitive on normalized DNS names and SHALL not extend to lookalike labels, parent names, or different TLDs.

#### Scenario: Family boundary
- **WHEN** `{n}.stg.example.com` is blocked
- **THEN** `3.stg.example.com` and `3x.stg.example.com` are blocked, while `abc.stg.example.com`, `3.other.example.com`, `stg.example.com`, and `3.stg.example.com.evil` are not blocked by this rule

#### Scenario: Marker boundary
- **WHEN** `447.*.site` is blocked
- **THEN** `447.alpha.site` and `447.sub.alpha.site` are blocked, while `447.site`, `447.alpha.com`, and `447x.alpha.site` are not blocked by this rule

#### Scenario: Not-yet-seen name
- **WHEN** a client queries a matching hostname absent from query history
- **THEN** the resolver blocks it immediately and records it as a campaign-caused block

### Requirement: Scope and policy precedence
A block rule SHALL have an explicit all-clients or single-client-IP scope, using the selected scope from the campaign row. Existing allowlist entries and filtering-pause behavior SHALL retain precedence over campaign blocks.

#### Scenario: Client-only block
- **WHEN** the rule is scoped to client A
- **THEN** a matching query from A is blocked and the same name from client B is not blocked by that rule

#### Scenario: Operator allow and pause
- **WHEN** a matching name is allowlisted or protection is paused
- **THEN** the campaign rule does not block it under the existing policy precedence

### Requirement: Rule lifecycle and visibility
Campaign blocks SHALL be durable, separately listed from review suppressions, attributable in query history, and revocable without changing existing exact-domain blocks or suppression records. A failed persistence or distribution step SHALL not be reported as a successful activation.

#### Scenario: Restart and multiple nodes
- **WHEN** a rule is active and a resolver restarts or a peer joins
- **THEN** matching queries on every hydrated resolver are blocked without requiring another observed candidate

#### Scenario: Revoke
- **WHEN** an operator revokes a campaign block
- **THEN** the rule stops blocking matching names on all nodes, subject to any other active rules or lists; review suppression state is unchanged

#### Scenario: Idempotent activation
- **WHEN** the same campaign/scope is activated twice
- **THEN** only one active rule exists and the operator sees the existing rule rather than two duplicates

#### Scenario: Stale campaign input
- **WHEN** a client submits a pattern that is invalid, does not match the claimed campaign shape, or is no longer available to block
- **THEN** the API rejects it and no rule is installed

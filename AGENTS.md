# AGENTS.md — Bifrost DNS

> This file is the authoritative reference for all agents working on this project.
> Do not deviate from architectural decisions documented here without explicit human approval.
> When in doubt, ask. Do not invent alternatives to settled decisions.

---

## Project Overview

Bifrost is a self-hosted, Kubernetes-native DNS filtering and forwarding server designed for a home network. It replaces a stack of AdGuard Home instances with a system that is fully understood, fully owned, and optimized for observability. The primary goals are:

- Fast, private, local DNS resolution with ad/tracker blocking
- Per-list block attribution (which blocklist is actually doing work)
- Per-client query visibility ("who is hitting this domain")
- Cache hit rates, upstream health, and block rate metrics
- GitOps-friendly configuration with live operational changes via UI
- Horizontal scaling in Kubernetes with transient Mnesia-based query cache propagation

This is not a research project. It is production infrastructure for a home network. Correctness, simplicity, and maintainability outweigh cleverness.

---

## Architecture

```
[DNS Clients on home network]
          │
          │ UDP :53
          ▼
  ┌───────────────┐        Unix Socket         ┌─────────────────────┐
  │  Rust Process │ ◄────────────────────────► │  Erlang/OTP Process │
  │  (hot path)   │                            │  (control plane)    │
  └───────────────┘                            └─────────────────────┘
          │                                             │
          │ UDP forward (cache miss)                    │
          ▼                                             ▼
  ┌───────────────┐                            ┌─────────────────────┐
  │ Upstream      │                            │     PostgreSQL      │
  │ (configured   │                            │  (operational cfg   │
  │  resolver)    │                            │   + query history   │
  └───────────────┘                            │   + metrics)        │
                                               └─────────────────────┘
                                                         ▲
                                               ┌─────────────────────┐
                                               │  Web UI             │
                                               │  (served by Erlang) │
                                               └─────────────────────┘
```

### Component Responsibilities

**Rust process — DNS hot path**
- Owns the UDP socket on port 53
- Receives all DNS queries
- Performs blocklist lookup against in-memory state (loaded by Erlang)
- Fabricates a DNS response for blocked domains per configured block mode (zero IP, NXDOMAIN, REFUSED, custom IP) and attaches EDE code 15
- Blocks alias cloaking (as AdGuard Home does): an answer, fresh or cached, whose CNAME chain or HTTPS/SVCB TargetName (RFC 9460, either mode; the root target `.` means the owner name and is skipped) reaches a blocklisted or manually blocked name gets the same block response, logged as an ordinary `BIFROST_BLOCK` attributed to the list that matched the target, with the answer's records attached (the query log shows "via CNAME/HTTPS/SVCB"). SVCB `ipv4hint`/`ipv6hint` are deliberately not checked yet; they belong with answer-IP blocking (TODO.md). Such answers are never cached or propagated. An allowlisted query name or target, a same-list `@@` exception, or paused protection skips it. Per-client blocks are not applied to targets, so a cached answer means the same for every client.
- Performs local cache lookup for clean domains; serves cached responses directly
- Forwards cache misses to knot-resolver; stores the response in the local cache and emits a `cache_store` IPC message for cluster-wide propagation

**Erlang/OTP process — control plane**
- Supervises the Rust process; restarts it on crash
- Reads ConfigMap at startup for structural config
- Reads Postgres at startup for operational config, falling back to the last-known Mnesia snapshot if Postgres is unavailable
- Merges structural and operational config and hydrates the Rust process over one bidirectional Unix socket
- Owns blocklist fetching, parsing, deduplication, and caching (Mnesia disc_copies)
- Manages Mnesia cluster membership via headless-Service discovery or the `BIFROST_CLUSTER_NODES` override
- Receives query events from Rust and writes bounded batches through a dedicated Postgres connection
- Monitors configured upstreams via periodic DNS probes (ETS-based health tracking)
- Serves the web UI (HTMX + Chart.js) and REST API via Cowboy
- Handles live operational config changes: writes to Postgres, snapshots them in Mnesia, and pushes updated state to Rust
- Relays cache entries across pods: receives `cache_store` from Rust, writes to Mnesia `ram_copies`, and cluster replication triggers a `store_cache` push to each peer's Rust

**PostgreSQL**

- External, pre-existing instance
- Stores operational config (blocklists added via UI, rewrite rules, allowlist entries)
- Stores the monthly-partitioned query log; retention is configured live through the `settings` table
- Stores per-list block attribution data
- Stores per-client query history
- Does not store structural config (that lives in ConfigMap)

---

## Technology Decisions

These decisions are settled. Do not propose alternatives without explicit instruction.

| Decision | Choice | Reason |
|---|---|---|
| DNS hot path | Rust | Zero GC pauses, raw UDP performance, safe memory model |
| Control plane | Erlang/OTP | Supervision trees, fault isolation, "let it crash" recovery, excellent for managing external processes and state |
| IPC between Rust and Erlang | Unix socket | Clean failure domain separation. A Rust crash does not take down the BEAM. NIFs were explicitly rejected for this reason. |
| Persistence | PostgreSQL | Pre-existing infrastructure, structured query support for per-client and per-list queries |
| Web UI | Cowboy + HTMX + Chart.js | Server-rendered HTML with hypermedia-driven interactivity (HTMX). No build pipeline, no JS framework. Chart.js from CDN for dashboards. |
| Config: structural | Kubernetes ConfigMap | GitOps, human-edited, requires restart to apply |
| Config: operational | PostgreSQL | Live changes via UI, no restart required. DNS upstreams, conditional routes, fallbacks, strategies, deadlines, reverse DNS, cache, block response and retention use ConfigMap values only as deployment defaults; explicit UI overrides live in the revisioned `dns_settings` row and are snapshotted to Mnesia. |
| DNS settings application | Versioned Rust settings acknowledgement | Deliberate exception to fire-and-forget IPC: `apply_dns_settings` carries revision, policy fingerprint and full validated settings. Rust compiles off the hot path, swaps atomically, then returns `dns_settings_applied` or `dns_settings_rejected` on a prioritised control-response path. Hydration does not send `reload_complete` until the current settings are acknowledged. |
| Routing privacy | Isolated routes | Most-specific conditional suffix wins on label boundaries. Routed queries never fall back to default upstreams. Private reverse PTR is never sent to defaults: explicit route, then optional private PTR resolvers, otherwise local NXDOMAIN. Non-IN classes are always refused locally. |
| Config reload | Reloader (Stakater) | Watches ConfigMap, triggers rolling restart. Erlang does not watch files or write to ConfigMap. |
| Blocklist cache | Mnesia disc_copies | Cluster-wide deduplication. One HTTP fetch per 24h per list, Mnesia replication propagates to all pods. Replaces per-pod flat-file cache. |
| Cluster discovery | Headless-Service SRV records, with an env override | `BIFROST_CLUSTER_SERVICE` names the headless Service; k8s publishes one SRV record per pod for each NAMED port, and the SRV target is the pod's stable FQDN — the host half of the node name. So the member list IS the Service and **scaling the StatefulSet needs no manifest edit**. Requires `publishNotReadyAddresses: true` or peers cannot resolve each other before Ready. Seeds are re-resolved on EVERY join attempt, never cached: at boot kube-dns may not list every pod yet, and a pod added later must be found without restarting anyone. `BIFROST_CLUSTER_NODES` (explicit comma-separated `name@host`) takes precedence — used by docker-compose and as the escape hatch. Neither set = single-node dev. Retry/creator-election gate on `clustered()` (is either var set?) rather than `seeds() =:= []`, because under discovery an empty resolve is transient — treating it as single-node would let two pods both elect themselves table creator. |
| Upstream health | ETS + periodic DNS probes | Lightweight, lost on restart (acceptable). Rust also holds down an upstream for 30s after a real query failure so a dead endpoint does not cost every cache miss a 2s timeout. |
| Horizontal scaling | Independent pods + Mnesia | Cross-pod state: blocklist cache + last-known operational config + filtering-pause state (Mnesia disc_copies); query cache/config broadcasts (Mnesia ram_copies, transient, fire-and-forget). Query log and upstream metrics remain per-pod. |
| Query cache propagation | Mnesia ram_copies (transient bus) | On cache miss, Rust fire-and-forgets the response to Erlang, which writes to Mnesia ram_copies. Cluster replication propagates to all peers, which push to their local Rust. Mnesia is a broadcast channel only — `cache_propagation` and `cache_evict` are NEVER read back, a row exists purely to make replication fire a table event. Because nothing read them, nothing deleted them either and they grew for the life of the node; `bifrost_cluster` now sweeps both every 5 min on the elected sweep leader. No cross-pod consistency guarantees: stale entries or missed broadcasts produce one extra upstream lookup on the affected pod. |
| Cluster job coordination | Two shapes, deliberately | **Singleton** (`bifrost_cluster:is_leader/1`, a `global` registered name) for work that is one indivisible sweep with no shard key, where running it on N nodes multiplies load on a shared resource: `bifrost_ptr_warmer` (one gateway resolver), `bifrost_domain_analyzer` (shared query_log + third-party RDAP), `bus_sweep` (clears the transient buses). MUST be called from the long-lived GenServer — `global` frees the name when the registered process dies. `bifrost_domain_analyzer` additionally runs ONE scan at a time cluster-wide: the GenServer monitors its scan worker and drops triggers while it runs, and a manual `scan_now/0` on a non-leader is forwarded to the leader, because overlapping scans both miss `rdap_cache` and double the third-party RDAP requests. **Per-resource lock** (`global:set_lock`) for shardable work, so different nodes handle different resources concurrently: one lock per blocklist in `bifrost_blocklist_manager:try_fetch/4`, which also means a node dying mid-fetch frees only that list instead of stalling all of them for a 24h cycle. `global:set_lock` requires a UNIQUE `LockRequesterId` (identical ids SHARE a lock) and `[node()\|nodes()]` (`[node()]` locks locally and always wins), and `Retries > 0` — with 0, simultaneous requesters can ALL be denied. |
| Cluster job visibility | `bifrost_cluster:singleton_jobs/0` catalogue | ONE source of truth: `{Name, GlobalName, TickIntervalSeconds, Description}`. The dashboard's Cluster Jobs panel maps over it, so adding a singleton is one line there and nothing else — a new job cannot be silently missing from the UI. Static rather than self-registering, because a job that registered on first tick would be absent for up to its whole interval after a boot, making "not yet ticked" indistinguishable from "missing". **No last-run heartbeat, deliberately:** holding the global name already proves the owning process is alive, and every job re-arms its timer unconditionally before returning, so a heartbeat would tick happily while the actual work failed every time — false confidence. Work that fails is surfaced by the error log. `bifrost_cluster_SUITE` asserts the names the real jobs claim at runtime match the catalogue, so a renamed `?LEADER` fails a test instead of orphaning a panel row. |
| Web UI/API auth | Stateless HMAC sessions + PBKDF2 | Single admin credential. Password hashed with PBKDF2-HMAC-SHA256 (210k iterations, OWASP 2023 floor), self-describing hash format (`pbkdf2$sha256$<iter>$<salt>$<hash>`) so iteration count can change without breaking existing hashes. Session tokens are stateless (`<expiry>.<hmac>`, HMAC-SHA256) — no server-side session store, so rotating the secret invalidates all sessions. All crypto from OTP `crypto`, no external deps. Secrets injected via env from a k8s Secret: `BIFROST_ADMIN_USER`, `BIFROST_ADMIN_PASSWORD_HASH`, `BIFROST_SESSION_SECRET`. If unconfigured, auth is disabled (dev). Enforced by `bifrost_auth_middleware` gating all UI/API routes. |
| PTR client-name enrichment | Out-of-band control-plane PTR | Reverse-DNS lookups turn client IPs into friendly names for the UI. **Never on the Rust hot path** — resolved out-of-band by `bifrost_ptr`/`bifrost_ptr_warmer` and cached in Postgres (`ptr_cache`, negative-cached, re-resolved on DHCP-lease staleness). RFC1918 PTR targets an operator-configured `ptr_resolver` (the LAN gateway), NOT the configured upstreams. If `ptr_resolver` is unset, PTR is disabled entirely and callers fall back to client label > raw IP. |
| Suspicious-domain analysis | `bifrost_domain_analyzer` + Threats page | Control-plane-only GenServer that periodically scans recently-forwarded domains for algorithmically-generated / throwaway ad domains (entropy, numbered subdomains, registration age via RDAP, CNAME cloaking, blocked siblings). A domain is queued only if `bifrost_api_handler:qualifies/1` holds: eligible name, score >= 3 **and two independent positive signals**. A leading number alone (every sharded service: `N.pool.ntp.org`, `0.gravatar.com`) is one signal, and `deep_subdomains` does not stack with it. Negative terms (`rdap:established`, `widespread`) and tags (`single_client`, header-probe `no_csp`/`permissive_cors`) never count as signals. Hit volume does not score. Contextual signals come from `bifrost_threat_context` (one batch of queries per scan): `cname_to_blocked:<target>` (+6 and qualifies on its own regardless of negative terms; Rust blocks these at resolution, so queued ones predate the block or are allowlisted; CNAME in stored answers into an ENABLED list or manual block, honouring same-list `@@` and the allowlist), `blocked_sibling` (+2), `newly_seen` (+1, only once query_log holds 30 days), `widespread` (-2, clients >= max(5, 25% of active)). Every scan first re-scores all `pending` rows under the current rules and DELETES those that no longer qualify, so a rule change cleans the queue; `blocked`/`dismissed` rows are operator decisions and never touched. Campaigns (`bifrost_threat_campaigns`) have two shapes: a **family** of >= 3 enumerated siblings under one parent (`{n}.stg.content-loader.com`), and a **marker** label across >= 3 DISTINCT registrable domains of a TLD (`447.*.site`), built only from names no family claimed. Suppressions carry `kind` (migration 017) and share ONE SQL matcher between dismissal and the analyzer filter. Qualifying candidates land in `suspicious_candidates` (Postgres) as `pending` for operator review on the Threats page. Read-only w.r.t. DNS resolution. Auto-block is **opt-in and off by default** (`settings` table: `auto_block_enabled`, `auto_block_min_score`, `auto_block_max_age_days`); the operator enables it only after the ranking proves itself. |
| RDAP enrichment | `bifrost_api_handler:rdap_cached/1,2` — ONE read-through cache, fetched via `bifrost_rdap` | Keyed on the **registrable base domain**, so every numbered-subdomain variant of one registration shares an entry. Rows carry a `status`: `ok`, `not_found` and `unsupported` (no `rdap_server/1` entry) are final and never re-requested; 429/5xx/timeout/unparseable are `transient` and become due again at `retry_at` (1h doubling to a 7d cap, never earlier than `Retry-After`). Caching every failure forever ruled out retry storms but meant one 429 dropped a domain from age scoring for good. **Age is computed at read** from `registered_on`; the stored `age_days` froze at lookup time, so a once-young domain kept `rdap:new_domain` and the auto-block age gate forever (column kept only for rolling-restart compat). **Every lookup first wins a claim**: one atomic `INSERT … ON CONFLICT DO UPDATE … WHERE due RETURNING` (`bifrost_rdap:claim_sql/0`) leases a `pending` row for 60s, so concurrent page loads, scans and pods never issue the same registry request twice — coordination is in Postgres, where the result lands, not a new singleton. `bifrost_rdap` (per node) paces each registry host to 1 req/s and pauses a host on 429. **The Clients page never contacts a registry inside a request**: `enrich_with_rdap/1` uses `async`, misses are queued (dedup, cap 100, 2 workers) and return `lookup => pending`; the page re-polls. The analyzer scan uses `sync` (inline, claimed, paced). Both consumers go through this one function; the enrich path used to call `rdap_lookup/1` directly and issued up to 10 live registry requests per page load. |
| Which RDAP fields score | Only the discriminating ones | `age_days` (graduated 3/2/1, and -3 with tag `rdap:established` at >= 730 days, which is what separates sharded infrastructure from numbered throwaways; the auto-block gate requires age < max_age so the discount never applies inside it) and `pending_delete` (3) score. `privacy_protected` and `has_transfer_lock` are **tags only**: registrant redaction is near-universal post-GDPR, and `clientTransferProhibited` is absent by ICANN rule for 60 days after registration (so "no lock" mostly restates "recently registered", which age already scores). A signal that fires on most of the internet is a constant offset, not a signal. Every field is optional — a cached negative entry or a partial registry response yields `undefined`, which MUST score 0, never crash the scan. |
| Reason-tag provenance | `rdap:` name prefix | Registry-derived reasons are namespaced (`rdap:new_domain`, `rdap:pending_delete`, …) so provenance travels with the tag into the Threats table, the per-client scan, and the raw `suspicious_candidates.reasons` rows. Both templates colour any `rdap:`-prefixed tag distinctly (sky, tooltip "From RDAP registry data") and strip the prefix for display — no shared catalogue of tag names to drift, because the name carries its own source. |

```yaml
upstreams:
  - address: 192.0.2.10  # upstream resolver 1
    port: 53
  - address: 192.0.2.11  # upstream resolver 2
    port: 53

cache:
  max_ttl: 3600
  min_ttl: 60
  max_entries: 100000

blocklists:
  default:
    - name: hagezi-pro
      url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt
      enabled: true
    - name: oisd-big
      url: https://big.oisd.nl/domainswild
      enabled: true

network:
  listen_address: "0.0.0.0"
  listen_port: 53
  unix_socket_path: /run/bifrost/ipc.sock

blocking:
  mode: zero_ip        # zero_ip | nxdomain | refused | custom_ip
  custom_ip: ""        # only used when mode: custom_ip

database:
  host: postgres.home.svc.cluster.local
  port: 5432
  name: bifrost
  user: bifrost
  # password via secret reference, not CM
```

Changes to this file require a `kubectl apply` followed by a Reloader-triggered rolling restart. This is intentional.

### What lives in PostgreSQL (operational config)

- Additional blocklists added via the UI (name, URL, enabled flag, added_at)
- Per-list enabled/disabled state overrides
- DNS rewrite rules (domain → IP or CNAME)
- Allowlist entries (domains that bypass blocklist matching)
- Per-client labels (friendly name for a client IP)

Changes here are live. Erlang applies them immediately and pushes updated state to Rust.

### Source of truth

- Git → ConfigMap. The cluster CM must always match git. Erlang never writes to the ConfigMap.
- Postgres is owned by the application. It is not version controlled.
- If both sources conflict on the same key, Postgres wins (operational overrides structural defaults).

---

## Development Practices

These are settled. Do not deviate without explicit instruction.

| Practice | Requirement |
|---|---|
| Test-driven development (TDD) | All Rust code MUST be written test-first. Every new function or method in the hot path (blocklist, cache, events, IPC message construction, DNS response building) MUST have a corresponding test before or simultaneous with the implementation. Tests live as `#[cfg(test)]` modules alongside the source. |
| Test scope | Test behavior, not plumbing. No mocks. Integration tests that exercise real sockets or DNS are acceptable for the forwarder and IPC; unit tests cover blocklist matching, cache logic, and event serialization. |
| Erlang tests | Required for the control plane. `bifrost_cluster_SUITE` runs TWO real nodes via OTP `peer` and covers replication, the per-list fetch lock, HTTP-304 propagation and singleton election; `bifrost_migrations_SUITE`, `bifrost_retention_SUITE` and `bifrost_rdap_cache_SUITE` run against real Postgres in a scratch database. New distributed behaviour MUST come with a test that asserts on the OTHER node, and MUST be mutation-checked (reintroduce the bug, prove the test fails). Single-node tests do not count as coverage for cluster behaviour. A cache MUST be tested through the code path that production calls, not just the cache function: the RDAP bug was a working cache that the page-load path never consulted, and a suite covering only `rdap_cached/1` passed while the bug was live. |
| CI gate | `.github/workflows/ci.yml` must pass before merge: Rust fmt/clippy (`-D warnings`)/test, Erlang EUnit + Common Test against a Postgres service, actionlint, kustomize render, image build. hk (`hk.pkl`) runs the same checks locally as pre-commit/pre-push hooks. |
| Commits and releases | Conventional-commit subjects are required: git-cliff derives versions and release notes from them, and silently drops non-conventional commits. Never bump versions or edit `CHANGELOG.md` by hand; the Release PR workflow does both via `scripts/bump-version.sh`. |

---

## Unix Socket Protocol

Communication between Erlang and Rust is over a Unix domain socket. Erlang is the server, Rust is the client. All messages are length-prefixed JSON frames (4-byte big-endian length header + UTF-8 JSON body).

### Erlang → Rust (control messages)

```json
{ "type": "begin_blocklist", "list_id": "hagezi-pro" }
{ "type": "load_blocklist", "entries": ["example.com", "ads.foo.com", "@@safe.ads.foo.com"], "list_id": "hagezi-pro" }
{ "type": "commit_blocklist", "list_id": "hagezi-pro" }
{ "type": "load_rewrites", "entries": [{ "domain": "nas.home", "target": "192.168.1.5" }] }
{ "type": "load_allowlist", "entries": ["github.com"] }
{ "type": "apply_dns_settings", "revision": 7, "fingerprint": "<policy hash>", "settings": { "schema_version": 1, "upstreams": {}, "routes": [], "cache": {}, "blocking": {}, "reverse_dns": {}, "retention_months": 6 } }
{ "type": "set_acl", "allowed_clients": ["192.168.0.0/16", "fd00::/8"] }
{ "type": "set_protection", "enabled": true }
{ "type": "store_cache", "domain": "example.com", "qtype": 1, "response": "<base64>", "ttl": 3600, "fingerprint": "<policy hash>", "variant": "0:0", "expires_at_ms": 1716000000000 }
{ "type": "reload_complete" }
```

### Rust → Erlang (event stream)

```json
{
  "type": "query_event",
  "client_ip": "192.168.1.42",
  "domain": "example.com",
  "qtype": 1,
  "action": "BIFROST_BLOCK",
  "client_rcode": "NXDOMAIN",
  "ede_code": 15,
  "list_id": "hagezi-pro",
  "latency_us": null,
  "queried_at": 1716000000
}
```

```json
{
  "type": "query_event",
  "client_ip": "192.168.1.42",
  "domain": "github.com",
  "qtype": 1,
  "action": "BIFROST_CACHE",
  "client_rcode": "NOERROR",
  "ede_code": null,
  "list_id": null,
  "latency_us": null,
  "queried_at": 1716000000
}
```

### Rust → Erlang (cache propagation)

Fire-and-forget, same reliability model as query events:

```json
{
  "type": "cache_store",
  "domain": "example.com",
  "qtype": 1,
  "response": "<base64-encoded DNS wire format>",
  "ttl": 3600
}
```

On receipt, Erlang decodes the response from base64 and writes to the Mnesia `cache_propagation` table (`ram_copies`). Mnesia replication propagates the record to all cluster nodes, where `blocklist_manager`'s subscription handler pushes a `store_cache` control message to the local Rust process. The Mnesia entry is not retained across restarts and serves only as a transient broadcast bus.

Action values: `BIFROST_BLOCK`, `BIFROST_CACHE`, `BIFROST_RW`, `BIFROST_ALLOW`, `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `UNKNOWN` (and other standard RCODEs)

Erlang batches query events before writing to Postgres. Events, cache broadcasts and ordinary control messages are asynchronous. The only application acknowledgement is for versioned DNS settings, because the UI and readiness must distinguish saved from applied. Policy-routed cache propagation uses the `cache_propagation_v2` transient bus; Rust rejects legacy, expired, mismatched-policy and invalid-variant entries. Delivery is connection-reliable (length-prefixed stream), and any reconnect triggers full Rust re-hydration, which restores all control state. Rust uses ONE bidirectional Unix-socket connection; two connections allowed control traffic to land on a socket Rust was not reading after a reconnect.

---

## PostgreSQL Schema

```sql
-- rcode_type covers standard IANA RCODEs and Bifrost-internal action codes.
-- Standard RCODEs are stable; new BIFROST_* values can be added via ALTER TYPE ADD VALUE (Postgres 12+, no table rewrite).
-- UNKNOWN is a catch-all for unrecognized upstream RCODEs to prevent write failures.
CREATE TYPE rcode_type AS ENUM (
    -- Standard IANA RCODEs
    'NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN',
    'NOTIMP', 'REFUSED', 'YXDOMAIN', 'YXRRSET',
    'NXRRSET', 'NOTAUTH', 'NOTZONE',
    -- Bifrost-internal action codes
    'BIFROST_BLOCK',   -- blocked by blocklist, no upstream contact
    'BIFROST_ALLOW',   -- allowlist forced through regardless of blocklist
    'BIFROST_RW',      -- rewrite rule applied, synthetic response returned
    'BIFROST_CACHE',   -- served from cache, no upstream contact
    -- Safety valve
    'UNKNOWN'          -- unrecognized upstream RCODE
);

-- Operational config: blocklists managed via UI or seeded from ConfigMap
CREATE TABLE IF NOT EXISTS blocklists (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    url             TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    source          TEXT NOT NULL DEFAULT 'ui',  -- 'configmap' or 'ui'
    domain_count    INTEGER,
    last_fetched_at TIMESTAMPTZ,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Operational config: DNS rewrites
CREATE TABLE IF NOT EXISTS rewrites (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain   TEXT NOT NULL UNIQUE,
    target   TEXT NOT NULL,  -- IP address or CNAME target
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Operational config: allowlist
CREATE TABLE IF NOT EXISTS allowlist (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain   TEXT NOT NULL UNIQUE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Client labels (friendly names for IPs)
CREATE TABLE IF NOT EXISTS clients (
    ip         INET PRIMARY KEY,
    name       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Query log: partitioned by month for efficient time-range queries and zero-cost partition drops.
-- Partitions are created and managed by the Erlang query_writer GenServer — no manual intervention required.
-- action:      what Bifrost decided (BIFROST_BLOCK, BIFROST_CACHE, NOERROR, NXDOMAIN etc.)
-- client_rcode: what the client actually received on the wire
-- ede_code:    RFC 8914 Extended DNS Error code (15=Blocked, 6=DNSSEC Bogus etc.) — NULL for most queries
-- qtype:       raw IANA DNS type code (1=A, 28=AAAA, 16=TXT etc.) stored as SMALLINT, no translation needed
-- latency_us:  NULL for BIFROST_BLOCK and BIFROST_CACHE (no upstream contact made)
-- list_id:     NULL unless action=BIFROST_BLOCK
CREATE TABLE IF NOT EXISTS query_log (
    id           BIGSERIAL,
    client_ip    INET NOT NULL,
    domain       TEXT NOT NULL,
    qtype        SMALLINT NOT NULL,
    action       rcode_type NOT NULL,
    client_rcode rcode_type NOT NULL,
    ede_code     SMALLINT,
    list_id      TEXT,
    latency_us   INTEGER,
    queried_at   TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (queried_at);

CREATE INDEX IF NOT EXISTS query_log_domain_idx ON query_log (domain);
CREATE INDEX IF NOT EXISTS query_log_client_idx ON query_log (client_ip);
CREATE INDEX IF NOT EXISTS query_log_list_idx   ON query_log (list_id);
CREATE INDEX IF NOT EXISTS query_log_time_idx   ON query_log (queried_at DESC);
CREATE INDEX IF NOT EXISTS query_log_action_idx ON query_log (action);

-- Per-list block attribution (materialized periodically from query_log)
CREATE TABLE IF NOT EXISTS list_stats (
    list_id      TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    block_count  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (list_id, period_start)
);
```

### Query Log Partitioning and Retention

`query_log` is partitioned by `queried_at` (monthly ranges). Partitions are created and maintained
by `bifrost_query_writer` — users never create partitions manually.

**Partition lifecycle (query_writer responsibility):**
- Maintenance runs on flush, but is gated on the calendar month actually changing. The writer keeps
  the last-maintained `{Year, Month}` in its state, so the work happens once per month per node
  rather than on every flush (it used to run twice per 500ms flush, which was pure waste).
- Each time it runs: ensure the current and next month partitions exist, then drop expired ones.

**Naming convention:** `query_log_YYYY_MM` (e.g. `query_log_2026_07`).

**Retention.** `query_log` is the only table that grows without bound. Measured at ~160 bytes/row
including indexes, so roughly 0.5GB/month at 100k queries/day and ~5GB/month at 1M queries/day —
size it against YOUR query volume, not the default.

Retention is whole months, read live from the `settings` table so it can change without a redeploy:

```sql
UPDATE settings SET value = '3' WHERE key = 'query_log_retention_months';
```

- Default `6` (migration `009_query_log_retention.sql`).
- `0` disables dropping entirely — unbounded growth, the pre-retention behaviour.
- Expiry is `DROP TABLE` of a whole partition: instantaneous, no VACUUM, no bloat.
- Partitions are enumerated via `pg_inherits`, never by globbing table names, so nothing outside the
  partition set can be dropped. Only fully-elapsed months can match; the current and next partitions
  are never candidates.

> **Deploying this for the first time drops every partition older than the retention window on the
> first flush.** Set `query_log_retention_months` before rolling out if you need longer history.

Covered by `bifrost_retention_SUITE` (6 tests, including a decoy non-partition table that must
survive and a guard that the current/next partitions are never dropped).

**No pg_partman required.** Vanilla Postgres 14+ only.

---

## Observability Requirements

These are the specific things the system must make visible. All are derived from query_log and list_stats.

| Metric | Source | Notes |
|---|---|---|
| Cache hit rate | query_log | `action = 'BIFROST_CACHE'` / total queries, over time |
| Overall block rate | query_log | `action = 'BIFROST_BLOCK'` / total, over time |
| Block rate per list | query_log | Group by `list_id` where `action = 'BIFROST_BLOCK'` |
| List utility | blocklists + query_log | Lists with zero block count in last N days flagged as inactive |
| Upstream health | Erlang ETS | Erlang polls knot-resolver periodically, tracks latency + error rate |
| Upstream latency | query_log | `latency_us` where `action` NOT IN ('BIFROST_BLOCK', 'BIFROST_CACHE') |
| Bifrost interventions | query_log | `action != client_rcode` — all rows where Bifrost modified the response |
| EDE distribution | query_log | Group by `ede_code` — surfaces DNSSEC failures, upstream errors etc. |
| Per-client query history | query_log | Filter by `client_ip` |
| "Who is hitting this domain" | query_log | Filter by `domain`, return distinct `client_ip` with counts |
| Per-client block rate | query_log | Filter by `client_ip`, `action = 'BIFROST_BLOCK'` |

---

## Erlang Supervisor Tree

```
bifrost_sup (one_for_one)
├── config_server        (GenServer — holds merged runtime config in state)
├── db_pool              (epgsql connection — UI/config reads; also runs migrations from priv/migrations/)
├── db_writer            (separate epgsql connection — query_log batch writes only)
├── cluster              (GenServer — forms/maintains distributed-Erlang + Mnesia cluster across pods)
├── dns_settings         (GenServer — revisioned operational DNS settings, Mnesia publication, Rust ACK status)
├── blocklist_manager    (GenServer — fetches, parses, deduplicates blocklists)
├── rust_supervisor (one_for_one)
│   ├── rust_port        (Port — owns the Rust OS process)
│   └── socket_server    (GenServer — Unix socket, sends/receives messages to Rust)
├── upstream_monitor     (GenServer — polls knot-resolver, updates ETS health table)
├── query_writer         (GenServer — buffers query events, batch writes to Postgres, manages monthly query_log partitions)
├── rdap                 (GenServer — per-registry RDAP pacing + background cache fill; claims are in Postgres)
├── domain_analyzer      (GenServer — periodically scans forwarded domains for algorithmically-generated ad/throwaway domains)
├── ptr_warmer           (GenServer — periodic reverse-DNS warming of active client IPs for friendly names in UI)
├── login_limiter        (GenServer/ETS — per-source failed-login throttling)
└── web_server           (Cowboy supervisor)
```

> Metrics are tracked in ETS by `upstream_monitor` (health/latency). There is no longer a
> dedicated `metrics_ets` process; the standalone counter owner was removed.

Crash behavior:
- `rust_port` crash → supervisor restarts it → the new Rust process connects to the Unix socket →
  `socket_server` calls `blocklist_manager:on_client_connected/0` → FULL re-hydration. This runs on
  EVERY connect, not just the first: a restarted Rust process has empty state and never received
  `reload_complete`, so it SERVFAILs every query until re-hydrated. Readiness reports
  `hydrating` for the duration, so k8s pulls the pod from the Service until it can filter again.
- Hydration failure → retried every 10s. Nothing else would retry, and the pod serves no DNS until
  it succeeds.
- `db_pool` crash → query_writer and blocklist_manager back off and retry; hot path is unaffected.
  `db_pool` traps exits because epgsql LINKS its socket process to the pool: an unreachable Postgres
  made that linked process exit, killing the pool, which tripped `bifrost_sup`'s restart intensity
  within milliseconds and took the WHOLE NODE down. Never remove that `process_flag(trap_exit, true)`.
- `web_server` crash → DNS resolution continues unaffected.

**Postgres is control-plane only; DNS MUST survive losing it.** Resolution is served entirely from
Rust's in-memory state. Blocklists AND a last-known snapshot of operational config (UI-added blocklist catalogue, rewrites, allowlist, manual/client blocks) persist in Mnesia `disc_copies`, so a node can cold-boot with Postgres down and still serve fully filtered DNS. A successful Postgres read refreshes the snapshot; a failure or 3s hydration timeout falls back to it. What degrades: query logging, the UI/API, and
operational config edits. Readiness therefore gates on hydration ONLY — never on DB health, or a
single Postgres outage would mark every pod NotReady at once and take the entire DNS cluster out of
its Service (a control-plane failure causing a total data-plane outage).

Probe endpoints (both auth-exempt — a gated path returns 401, which is outside k8s's 200-399 success
range and would CrashLoopBackOff the pod):
- `/api/health/live` — liveness/startup. Is the BEAM answering? No DB, no hydration dependency.
- `/api/health` — readiness. 200 once hydrated, 503 while `hydrating`. Reports `db` for observability.

---

## What Is Explicitly Out of Scope

Do not implement, suggest, or scaffold any of the following:

- **Prometheus exporter** — metrics are in Postgres and ETS, export can be added later if wanted
- **Grafana** — not wanted, not needed
- **Erlang NIFs** — rejected. Unix socket is the IPC mechanism. A Rust crash must not take down the BEAM.
- **Erlang writing to ConfigMap** — never. Erlang does not touch Kubernetes API for config writes.
- **Full recursive resolver in Rust** — Rust forwards to upstream resolver. It does not walk the DNS tree.
- **DNSSEC validation in Rust** — upstream resolver handles this.
- **AdGuard Home** — this project replaces it as the primary DNS filter. AdGuard instances may serve as upstream resolvers in the interim.
- **File watching for ConfigMap changes** — Reloader handles restarts. Erlang reads config once at startup.

---

## Project Structure

```
bifrost/
├── AGENTS.md
├── docker-compose.yml         # dev environment (single node)
├── docker-compose.cluster.yml # dev environment (multi-node cluster)
├── rust/                      # Rust hot path
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── listener.rs        # UDP socket + DNS message handling
│       ├── blocklist.rs       # in-memory blocklist state
│       ├── cache.rs           # DNS response cache
│       ├── acl.rs             # client source-address ACL
│       ├── forwarder.rs       # upstream forwarding
│       ├── ipc.rs             # Unix socket client, message protocol
│       ├── events.rs          # query event construction
│       ├── rewrites.rs        # rewrite-rule state
│       ├── allowlist.rs       # allowlist state
│       └── client_blocks.rs   # per-client manual block state
├── erlang/                    # Erlang/OTP control plane
│   ├── rebar.config
│   ├── Dockerfile
│   ├── config/
│   │   ├── vm.args
│   │   └── sys.config
│   └── apps/bifrost/
│       ├── src/
│       │   ├── bifrost_app.erl
│       │   ├── bifrost_sup.erl
│       │   ├── bifrost_config_server.erl
│       │   ├── bifrost_blocklist_manager.erl
│       │   ├── bifrost_mnesia.erl
│       │   ├── bifrost_opconfig.erl       # last-known operational config snapshot
│       │   ├── bifrost_domain.erl         # canonical domain normalization
│       │   ├── bifrost_cluster.erl
│       │   ├── bifrost_migrations.erl      # runs priv/migrations/*.sql
│       │   ├── bifrost_rust_supervisor.erl
│       │   ├── bifrost_rust_port.erl
│       │   ├── bifrost_socket_server.erl
│       │   ├── bifrost_upstream_monitor.erl
│       │   ├── bifrost_query_writer.erl
│       │   ├── bifrost_db_pool.erl
│       │   ├── bifrost_domain_analyzer.erl # suspicious-domain detection
│       │   ├── bifrost_threat_context.erl  # contextual threat signals (CNAME, siblings, spread)
│       │   ├── bifrost_threat_campaigns.erl # campaign grouping + expiring suppressions
│       │   ├── bifrost_rdap.erl            # RDAP claim/pace/retry + background fill
│       │   ├── bifrost_ptr.erl             # reverse-DNS client-name enrichment
│       │   ├── bifrost_ptr_warmer.erl      # periodic PTR warming
│       │   ├── bifrost_auth.erl            # password hashing + session tokens (OTP crypto)
│       │   ├── bifrost_login_limiter.erl   # per-source login throttling
│       │   ├── bifrost_template.erl
│       │   ├── bifrost_view.erl
│       │   ├── bifrost_web_server.erl
│       │   └── web/
│       │       ├── bifrost_router.erl
│       │       ├── bifrost_api_handler.erl
│       │       ├── bifrost_ui_handler.erl
│       │       ├── bifrost_auth_handler.erl     # login/logout endpoints
│       │       └── bifrost_auth_middleware.erl  # session gate for UI/API
│       ├── priv/
│       │   ├── static/                 # CSS, bundled chart.js fallback
│       │   ├── templates/              # HTML templates
│       │   ├── migrations/             # numbered SQL migrations (001..NNN)
│       │   └── builtin_blocklists.json # seed blocklist catalog
│       └── test/                       # EUnit + Common Test suites
├── dev/
│   └── config.yaml            # dev config (Erlang term format)
└── k8s/                       # Kubernetes manifests
    ├── kustomization.yaml
    ├── namespace.yaml
    ├── configmap.yaml
    ├── statefulset.yaml
    ├── service.yaml
    ├── service-anycast.yaml
    ├── networkpolicy.yaml
    ├── pdb.yaml
    └── secret.yaml            # credential template; intentionally not in kustomization
```

**Kubernetes assumptions**
- Single container per pod containing both the Rust binary and the Erlang release. No sidecars.
- Erlang is the init process of the container. It spawns the Rust binary as a child OS process via `open_port`. Kubernetes never owns the Rust process — OTP supervision does.
- If the Rust process crashes, Erlang's supervisor tree detects the port exit and restarts it directly. Kubernetes is not involved in Rust restarts.
- The Unix socket at `/run/bifrost/ipc.sock` is internal to the container filesystem. No shared volumes or emptyDir mounts are needed for IPC.
- The only thing Kubernetes restarts is the pod itself, which means the entire Erlang node. This is intentional and correct.
- DNS service exposed via a Kubernetes Service of type ClusterIP with externalIPs or via a LoadBalancer
- Reloader (Stakater) is installed in the cluster and watching the ConfigMap

**Startup sequence**
1. The application validates the distributed-Erlang cookie when clustering is configured, initializes Mnesia tables, and starts the supervisor tree.
2. The config server reads structural config from the mounted ConfigMap; the DB workers connect and run migrations when Postgres is available.
3. The cluster manager discovers peers through the headless Service (or explicit `BIFROST_CLUSTER_NODES`) and joins Mnesia.
4. Erlang starts the Rust process and the Unix-socket server; the web server and remaining workers start independently.
5. Rust connects over one bidirectional socket, which triggers full hydration on every connection.
6. Erlang sends upstream, block mode, cache, ACL, staged blocklist, rewrite, allowlist, manual/client block, and protection state. Operational config comes from Postgres or its last-known Mnesia snapshot.
7. Erlang sends `reload_complete`; Rust begins normal DNS service and readiness becomes healthy.
8. Enabled blocklists refresh periodically and operational changes are pushed live without restarting the pod.

Rust must not accept DNS queries until it receives `reload_complete`. Before that message it should return SERVFAIL to any query received.

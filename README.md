<p align="center">
  <img src="erlang/apps/bifrost/priv/static/bifrost-wordmark.png" alt="Bifrost" width="460">
</p>

<p align="center">
  <b>A self-hosted, Kubernetes-native DNS filter and forwarder for a home network.</b><br>
  Rust on the packet path. Erlang/OTP everywhere else.
</p>

---

Bifrost blocks ads and trackers at the DNS layer, forwards everything else to
resolvers you choose, and tells you exactly what happened to each query: which
blocklist caught it, which client asked, whether it came from cache, and how long
upstream took.

It was built to replace a set of AdGuard Home instances with something whose
every moving part is understood and owned. It is production infrastructure for
one home network, not a product. Read the [Status and limitations](#status-and-limitations)
section before you deploy it anywhere you care about.

## What it does

**Filtering**
- Multiple blocklists (hosts, plain domain, and adblock-style `||domain^` / `@@` exceptions), fetched on a 24h cycle with HTTP conditional requests
- **Per-list attribution**: every block records the list that caused it, so you can see which lists do the work and which are dead weight
- Allowlist, rewrites (domain → IP or CNAME), manual blocks, and per-client blocks
- Block response modes: zero IP, `NXDOMAIN`, `REFUSED`, or a custom IP. Each one carries [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) EDE code 15 (Blocked)
- A cluster-wide, timed "pause filtering" switch that survives restarts

**Forwarding**
- UDP and TCP on the listen port
- Multiple upstreams with selectable strategies, deadlines, and fallbacks
- Conditional routing by domain suffix. The most specific suffix wins, and routed queries **never** fall back to your default upstreams
- Private reverse lookups (RFC 1918 PTR) are never sent to public resolvers. They go to an explicit route, an optional LAN resolver, or get a local `NXDOMAIN`
- Response cache with TTL clamping, keyed by the effective DNS policy, so changing a route can't serve an answer cached under the old one
- Upstream health probes, plus a 30s hold-down after a real failure so one dead resolver doesn't add a timeout to every cache miss

**Visibility**
- Query log in Postgres, partitioned by month, with retention you can change at runtime
- Dashboard: cache hit rate, block rate overall and per list, upstream latency and health, EDE distribution
- Per-client history and "who is hitting this domain"
- Friendly client names from labels or out-of-band reverse DNS against your gateway
- **Threats page**: a periodic scan for algorithmically generated or throwaway domains (entropy, numbered subdomains, RDAP registration age, burst traffic). Candidates are queued for **you** to review. Auto-blocking exists but is **off by default**

**Operations**
- Horizontal scaling as a StatefulSet. Pods find each other through a headless Service, so scaling needs no peer-list edits
- Blocklists are fetched **once per cluster** and replicated through Mnesia. Cache entries are broadcast to peers
- DNS keeps working when Postgres is down: pods cold-boot from a last-known config snapshot in Mnesia
- Settings changes are versioned and acknowledged. The UI shows the difference between *saved* and *applied on every pod*
- Single-admin web UI (HTMX + Chart.js, no frontend build step) with PBKDF2 password hashing and stateless HMAC sessions

## Architecture

```
          DNS clients
               │  UDP/TCP :53
               ▼
     ┌───────────────────┐   one Unix socket,    ┌──────────────────────┐
     │   Rust resolver   │ ◄── length-prefixed ─► │  Erlang/OTP node     │
     │   (hot path)      │      JSON frames       │  (control plane)     │
     └───────────────────┘                        └──────────────────────┘
               │ cache miss                          │        │       │
               ▼                                     ▼        ▼       ▼
        upstream resolvers                     PostgreSQL  Mnesia  Web UI / API
                                                           (peers)
```

**Rust** owns the socket. It answers from in-memory state: ACL, blocklists,
allowlist, rewrites, cache, and routing. It forwards misses upstream and emits a
fire-and-forget event for every query. It never talks to Postgres, the network
control plane, or the UI.

**Erlang** is PID 1 in the container. It spawns and supervises the Rust process,
fetches and parses blocklists, hydrates Rust over the socket, batches query
events into Postgres, runs the cluster, serves the UI, and pushes live config
changes. When Rust restarts or reconnects, Erlang re-sends the full state. Until
that finishes, Rust answers `SERVFAIL` and the readiness probe reports
`hydrating`, so Kubernetes takes the pod out of rotation.

**PostgreSQL** (external, existing instance) holds operational config and the
query log. It is control-plane only. Losing it degrades logging, the UI, and
config edits. DNS resolution keeps working.

**Mnesia** has two jobs. It is the durable cluster store (blocklist cache,
last-known operational config, pause state), and it is a transient broadcast bus
for cache entries and settings.

## Why two languages

The language bar on this repo shows Erlang, Rust, and HTML in roughly comparable
amounts. That's a fair question to ask about a DNS filter, so here is the answer.

**The first plan was all Erlang. It was the wrong call.** The BEAM is
excellent at the control-plane half of this problem and a poor fit for the
other half:

- **Memory density.** A few combined blocklists add up to millions of domains.
  Holding them as Erlang terms or in ETS costs several times what a compact Rust
  structure does, and it all sits in a garbage-collected heap.
- **Predictable per-packet latency.** Every query wants parse → lookup → answer
  with no allocator surprises and no scheduler or GC jitter. Rust offers that
  without effort.
- **DNS wire format.** `hickory-proto` is a mature, well-tested DNS codec.
  Erlang's options are thinner, and hand-rolling EDNS/EDE handling is where
  subtle bugs live.

**All-Rust would have been wrong in the other direction.** Supervising an
external process, forming a cluster, replicating state across pods, electing
singleton jobs, and recovering from crashed database connections are what OTP
and Mnesia exist for. Reproducing that in Rust means rebuilding a worse
distributed runtime.

**Why a Unix socket and not NIFs:** a crash in Rust must not take the BEAM down
with it. Over a socket, a Rust panic is a supervised child restart followed by
a re-hydration. As a NIF, it kills the node.

**What this costs, honestly:**
- Two toolchains, two test suites, and an IPC protocol that has to stay in sync on both sides
- Hydration on every reconnect, a `SERVFAIL` window while it runs, and readiness logic to hide that window from clients
- One deliberate exception to fire-and-forget IPC: DNS settings changes carry a revision and need an acknowledgement from Rust, because "saved" and "actually applied" have to be distinguishable
- Debugging across the seam is harder than debugging either side alone

That trade was made on purpose and hasn't been regretted, but it isn't free.

Rough size (source lines, approximate):

| Part | Lines |
|---|---|
| Rust resolver (`rust/src`, tests inline) | ~5,000 |
| Erlang control plane (`erlang/apps/bifrost/src`) | ~6,400 |
| Erlang tests (EUnit + Common Test) | ~3,900 |
| HTML templates + CSS | ~2,300 |

## Quick start (docker compose)

```sh
docker compose up -d --build
```

This starts Postgres and one Bifrost node:

| | |
|---|---|
| DNS | `localhost:1053` (UDP + TCP) |
| Web UI | http://localhost:8081 |

```sh
dig @127.0.0.1 -p 1053 example.com
dig @127.0.0.1 -p 1053 pagead2.googlesyndication.com   # blocked: 0.0.0.0, EDE 15
```

Dev config is [`dev/config.yaml`](dev/config.yaml) (Erlang term format, mounted
live). **Set the upstream addresses and `ptr_resolver` to your own resolvers
before you start.** Templates and `.erl` changes are baked into the image, so rebuild
with `docker compose up -d --build bifrost` after editing them.

With no admin credentials set, auth is disabled in dev. To try a multi-node
cluster locally, use `docker compose -f docker-compose.cluster.yml up -d --build`.

## Kubernetes

```sh
kubectl apply -k k8s/
```

This deploys a 3-replica StatefulSet with a small PVC per pod for Mnesia,
per-pod LoadBalancer IPs for DNS, a PodDisruptionBudget, and a NetworkPolicy.
Before applying:

- An **external PostgreSQL** reachable at the host in `k8s/configmap.yaml`. Migrations run on boot, so the user needs DDL rights
- **[Reloader](https://github.com/stakater/Reloader)** installed. A ConfigMap change triggers a rolling restart, and Bifrost never watches files
- **Secrets** populated from the template in `k8s/secret.yaml` (Erlang cookie, DB password, session secret, admin user, PBKDF2 hash). It is intentionally excluded from the kustomization
- The StatefulSet **image** points at the published `ghcr.io/crainte/bifrost` release. Change it if you build your own

Why there is one IP per pod instead of a shared VIP, the anycast alternative,
scaling, and secret generation are covered in [`k8s/README.md`](k8s/README.md).

### Configuration model

| Kind | Where | How it changes |
|---|---|---|
| Structural (listen address, DB, default blocklists, deployment defaults) | ConfigMap | Git → `kubectl apply` → Reloader rolling restart |
| Operational (UI blocklists, allow/block rules, rewrites, client labels, DNS settings overrides, retention) | PostgreSQL | Live from the UI/API, pushed to every pod, no restart |

If both define the same key, Postgres wins. Erlang never writes to the ConfigMap.

### Probes

- `/api/health/live`: liveness/startup. Is the BEAM answering?
- `/api/health`: readiness. `503` while hydrating, `200` after. It **does not** gate on Postgres, because a database outage must not pull every pod out of the Service at once

## Development

```sh
# Rust
cd rust
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Erlang
cd erlang
rebar3 eunit
rebar3 ct    # needs Postgres; see below
```

Rust code is written test-first, with tests inline under `#[cfg(test)]`. The
Common Test suites use real infrastructure instead of mocks. Database suites
create a scratch database on `BIFROST_TEST_DB_HOST` / `BIFROST_TEST_DB_PORT`
(default `postgres:5432`). `bifrost_cluster_SUITE` boots two real nodes via OTP
`peer` and asserts on the *other* node, because single-node tests don't prove
cluster behaviour.

### Git hooks

[mise](https://mise.jdx.dev) pins the tooling and [hk](https://hk.jdx.dev) runs
the hooks:

```sh
mise install && hk install
```

- **pre-commit:** `cargo fmt` (fixes are staged), clippy with warnings denied, actionlint
- **pre-push:** `cargo test`, and EUnit in an `erlang:29` container (needs Docker). Each runs only when its side of the tree changed

`hk check --all` runs the pre-commit checks on demand.

### CI and releases

Every pull request and every push to main runs: Rust fmt, clippy and tests;
Erlang EUnit and Common Test against a Postgres service container; actionlint;
a kustomize render; and an image build. Dependabot opens weekly `chore(deps)`
PRs for crates, actions and Docker base images. Hex packages (`rebar.lock`)
are updated by hand, because Dependabot doesn't support rebar3.

A release takes two steps and works with a protected `main`:

1. **Actions → Release PR → Run workflow.** [git-cliff](https://git-cliff.org)
   derives the next version from [conventional commits](https://www.conventionalcommits.org)
   (`feat` → minor, `fix` → patch; you can force a bump or an exact version).
   The workflow opens a PR that bumps the version in `Cargo.toml`, the OTP app,
   the relx release and the StatefulSet image, and updates `CHANGELOG.md`. The
   release notes go in the PR body.
2. **Merge the PR.** The Release workflow runs the full CI as a gate, then
   tags `vX.Y.Z`, creates the GitHub release, and publishes
   `ghcr.io/crainte/bifrost:X.Y.Z`, `:X.Y` and `:latest`.

A version is released when it has a `CHANGELOG.md` entry but no tag yet, so a
failed release can be retried by running the Release workflow again. Merge
commits, `chore(release)`, `chore(deps)` and non-conventional commits are left
out of the notes.

Optional repository setting:
- `RUNNER` variable: a self-hosted runner label (for example an ARC scale set)
  for the Rust, Erlang and image jobs on trusted events. Pull requests,
  including forks, always run on GitHub-hosted runners.

### Layout

```
rust/          DNS hot path (listener, cache, blocklist, routing, forwarder, IPC)
erlang/        OTP application, release config, Dockerfile
  apps/bifrost/priv/migrations/   numbered SQL migrations, applied on boot
  apps/bifrost/priv/templates/    server-rendered HTML
dev/           docker-compose config
k8s/           manifests
scripts/       release helpers
mise.toml      pinned dev tooling (hk, git-cliff, actionlint)
hk.pkl         git hooks
.github/       CI and release workflows
```

## Status and limitations

To be upfront about what this is and isn't:

- **Single-user, single-site.** One admin credential, with no roles and no multi-tenancy
- **Not a recursive resolver.** It forwards. DNSSEC validation is your upstream's job
- **No DoH/DoT/DoQ listener.** Plain DNS over UDP/TCP only. Put it behind something else if you need encrypted transport to clients
- **No Prometheus exporter.** Metrics live in Postgres and ETS and are shown in the built-in UI. That's a deliberate choice for now
- **Upstream health is per pod.** It lives in ETS, is lost on restart, and the UI shows the pod you're connected to. The query log has no pod/node column, so you can't tell which pod answered a query
- **The cache is eventually consistent across pods.** A missed broadcast costs one extra upstream lookup and nothing more
- **Retention drops whole months.** The first deploy with retention enabled drops every partition older than the window. Set `query_log_retention_months` first if you need more history
- **Assumes Kubernetes and an existing Postgres.** docker compose is for development
- **Version 0.1.0.** It runs a real home network, but the API, schema, and IPC protocol may still change without a migration story beyond the numbered SQL files

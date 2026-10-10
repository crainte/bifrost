# Bifrost — Kubernetes deployment

Deploys a 3-replica Bifrost DNS cluster:

```sh
kubectl apply -k k8s/
```

The kustomization applies the namespace, ConfigMap, Services, StatefulSet,
NetworkPolicy and PodDisruptionBudget. It does **not** apply `secret.yaml` or
`service-anycast.yaml`.

## Prerequisites (not managed here)

- **External PostgreSQL**, reachable at the host set in `configmap.yaml`.
  Migrations run automatically on boot, so the DB user needs DDL rights.
- **[Reloader](https://github.com/stakater/Reloader)** installed cluster-wide.
  The StatefulSet is annotated so that a change to the ConfigMap or Secret
  triggers a rolling restart. Bifrost never watches files.
- **A populated Secret.** `secret.yaml` is a template full of placeholders (see below).
- **A container image.** The StatefulSet uses the published
  `ghcr.io/crainte/bifrost:<version>` image, which each release bumps. Point it
  at your own registry if you build the image yourself, and pin a digest if you
  want immutability.
- **A LoadBalancer implementation** (MetalLB, Cilium, a cloud LB) that can hand
  out one IP per DNS Service.

## Configuration

`configmap.yaml` holds the structural config in Erlang term format: listen
address, database host, default blocklists, and the deployment defaults for
upstreams, routing, cache and block mode. The upstream and PTR addresses in it
are documentation placeholders (`192.0.2.x`), so replace them with your own
resolvers.

Anything changed later in the web UI is stored in Postgres and overrides the
ConfigMap defaults without a restart. Editing the ConfigMap itself means
`kubectl apply`, after which Reloader rolls the pods.

## Secrets (`secret.yaml`)

All values are injected as env vars from the `bifrost-secrets` Secret. Never
commit real values. Use sealed-secrets, SOPS, or an external secret manager.

| Key | Purpose | Generate |
|-----|---------|----------|
| `BIFROST_COOKIE` | Erlang distribution cookie. **Must be identical on every pod.** Placeholder or short values are refused. | `openssl rand -hex 32` |
| `BIFROST_DB_PASSWORD` | Postgres password (kept out of the ConfigMap) | your DB password |
| `BIFROST_SESSION_SECRET` | Signs UI session tokens. Rotating it logs everyone out. | `openssl rand -hex 32` |
| `BIFROST_ADMIN_USER` | Web/API admin login | — |
| `BIFROST_ADMIN_PASSWORD_HASH` | PBKDF2 hash of the admin password (never the plaintext) | see below |

Generate the password hash with the app's own hasher so the format matches:

```sh
kubectl exec -n bifrost bifrost-0 -- /opt/bifrost/bin/bifrost eval \
  'io:format("~s~n",[bifrost_auth:hash_password(<<"your-password">>)]).'
```

## Authentication

Every UI page and `/api/*` route is gated by `bifrost_auth_middleware`, except
`/login` and the two health probes. Auth accepts either a signed session token
(browser: log in at `/login`) or HTTP Basic (API clients).

## DNS service topology

`service.yaml` gives **each pod its own LoadBalancer IP** (`bifrost-dns-0/1/2`),
each pinned to its pod via the `statefulset.kubernetes.io/pod-name` label.

**Why one IP per pod instead of a shared VIP:** a stub resolver treats each
configured nameserver IP as pass/fail. One query timeout marks that whole IP as
dead, and the stub moves on to the next. If N pods sat behind one VIP, a single
pod blip (such as a rolling restart, while the dead pod is still an endpoint)
would make clients see the whole resolver as flaky, with nowhere to fail over
to. With per-pod IPs, a dead pod degrades exactly one nameserver and clients
fail over from IP to IP. List every per-pod external IP as a separate
nameserver in your DHCP or client config.

**Scaling takes two steps.** The Erlang cluster grows by itself.
`BIFROST_CLUSTER_SERVICE` points at the headless Service, and peers are resolved
from its SRV records on every join attempt, so there is no seed list to
maintain. Going from 3 to 4 pods means:

1. `replicas: 4` in `statefulset.yaml`
2. a new `bifrost-dns-3` Service in `service.yaml`

Step 2 can't be skipped: the per-pod LoadBalancer *is* the failover mechanism,
so a pod without its own external IP takes no client traffic. The anycast
topology below removes step 2 as well, at the cost of needing BGP.

To pin an explicit member list instead of discovering one, set
`BIFROST_CLUSTER_NODES` (comma-separated `name@host`). It takes precedence, and
it is what `docker-compose.cluster.yml` uses. To check discovery on a live
cluster:

```sh
kubectl -n bifrost exec bifrost-0 -- /opt/bifrost/bin/bifrost eval \
  'bifrost_cluster:seeds().'
```

### Alternative: anycast (`service-anycast.yaml`)

Not applied by default. With BGP available (MetalLB or Cilium BGP, peered with
a BGP-capable router), `service-anycast.yaml` provides 2 shared VIPs advertised
from every healthy node and withdrawn within the BGP hold timer when a node
goes unhealthy. This decouples the number of DNS IPs from the number of pods
(2 IPs, N pods), which is the model public resolvers use.

Requirements: BGP mode (L2/ARP mode does **not** give real anycast) and
`externalTrafficPolicy: Local`. To switch, replace `service.yaml` with
`service-anycast.yaml` in `kustomization.yaml` and fill in your reserved VIPs
(the examples use `198.51.100.x` placeholders).

## Probes

Both probe paths are auth-exempt. A gated path would return 401, which
Kubernetes counts as failure, and the pod would crash-loop.

- **Startup / liveness** → `/api/health/live`. Checks only that the BEAM is
  answering. It has no dependency on the database or on hydration, so a
  transient blip never kills a healthy pod.
- **Readiness** → `/api/health`. Returns `503` while the Rust resolver is being
  hydrated (it answers `SERVFAIL` until then) and `200` once it can filter.
  Readiness deliberately does **not** depend on Postgres. DNS is served from
  in-memory state and keeps working without the database, and gating on it
  would let a single Postgres outage pull every pod out of the Service at once.
  The response still reports `db` status, for visibility.

## Persistence

Each pod gets a 1Gi PVC for Mnesia. It holds the `disc_copies` tables (the
blocklist cache, a last-known snapshot of operational config, and the filtering
pause state) plus the schema. This means:

- a rolling restart doesn't re-fetch every blocklist
- a pod can cold-boot and serve fully filtered DNS while Postgres is down

The transient buses (cache propagation, settings broadcasts) are `ram_copies`
and re-form when a node rejoins.

## Resources

An idle pod uses roughly 0.6–0.8 GiB. A forced refresh of every blocklist peaks
around 1.8 GiB. The StatefulSet requests `1Gi` and limits at `2560Mi`. Scale
these to the size of your blocklists.

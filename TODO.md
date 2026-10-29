# TODO — AdGuard Home parity

Gaps found comparing Bifrost's filtering with AdGuard Home, which it replaces.
Done so far: CNAME cloaking (#25), HTTPS/SVCB alias targets.

In priority order:

1. **Answer-IP blocking.** AdGuard blocks an answer whose A/AAAA address matches
   an IP rule in a list. Bifrost matches names only, and IP rules in lists are
   skipped by the parser. Needs IP rule parsing (`bifrost_blocklist_manager`),
   an IP/CIDR set per list in `rust/src/blocklist.rs`, and a check beside
   `blocked_alias` in `listener.rs`. Include SVCB `ipv4hint`/`ipv6hint` here.

2. **List-rule coverage.** Rules with `$dnstype`, `$client`, `$denyallow` or
   `$dnsrewrite`, and `/regex/` and `*` wildcard rules, are dropped today
   (`adblock_rule/1`, `modifiers/1`). Dropping is deliberate (better than
   over-blocking) but the loss is silent. Support what the model allows, and
   show a per-list count of skipped rules on the Blocklists page.

3. **`use-application-dns.net` canary.** Answer NXDOMAIN so Firefox does not
   switch itself to its own DoH and bypass Bifrost. Needs a special-name path
   that applies even when filtering is paused.

4. **Query handling.** Refuse `ANY` queries, optional AAAA suppression, and a
   per-client rate limit.

## Not planned

Recorded so they are not proposed again:

- **DNS rebinding protection** (blocking public names that resolve to private
  addresses). Public names here deliberately resolve to internal IPs
  (e.g. `lighthouse.itai.moe`); this would break them.
- Safe Search, parental control, Safe Browsing, blocked services.
- DoH / DoT / DoQ listeners.

#!/usr/bin/env bash
# Set the project version everywhere it is declared.
#   scripts/bump-version.sh 0.2.0
# Used by the Release workflow; safe to run locally.
set -euo pipefail

version="${1:?usage: $0 <version>}"
version="${version#v}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "not a semver version: $version" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

# Rust package version (first `version =` line is [package]).
sed -i "0,/^version = \".*\"/s//version = \"$version\"/" rust/Cargo.toml
# Matching Cargo.lock entry.
sed -i "/^name = \"bifrost-resolver\"$/{n;s/^version = \".*\"/version = \"$version\"/}" rust/Cargo.lock
# OTP application and relx release.
sed -i "s/{vsn, \"[^\"]*\"}/{vsn, \"$version\"}/" erlang/apps/bifrost/src/bifrost.app.src
sed -i "s/{release, {bifrost, \"[^\"]*\"}/{release, {bifrost, \"$version\"}/" erlang/rebar.config
# Kubernetes manifest pins the released image.
sed -i "s|image: ghcr.io/crainte/bifrost:[^ ]*|image: ghcr.io/crainte/bifrost:$version|" k8s/statefulset.yaml

grep -q "^version = \"$version\"" rust/Cargo.toml
grep -q "{vsn, \"$version\"}" erlang/apps/bifrost/src/bifrost.app.src
grep -q "{release, {bifrost, \"$version\"}" erlang/rebar.config
grep -q "image: ghcr.io/crainte/bifrost:$version" k8s/statefulset.yaml
echo "version set to $version"

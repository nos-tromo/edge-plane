#!/usr/bin/env bash
# Verifies landing/tokens.css still carries the vendoring header this repo
# requires: a canonical-source line and a pinned commit/tag. Same spirit as
# the scripts/bundle-lib.sh drift-check: a local header check rather than a
# live fetch against nos-tromo/infra-ui, because this repo is airgap-first
# and CI must not reach the network — not because infra-ui lacks a stable
# ref. infra-ui now cuts release tags (e.g. v0.8.0) and the header pins to
# one of those, same as a commit SHA would.
# Re-vendoring (pulling a fresh copy and updating the pinned ref) is a
# documented manual step — see README.md's "Portal design tokens" section
# and landing/tokens.css's own header.
set -euo pipefail

FILE="landing/tokens.css"

[[ -f "$FILE" ]] || { echo "missing $FILE" >&2; exit 1; }

grep -q "Vendored verbatim from nos-tromo/infra-ui" "$FILE" \
  || { echo "$FILE is missing its vendoring header (canonical source + pinned ref) — never hand-edit it without one" >&2; exit 1; }

grep -qE "(tag v[0-9]+\.[0-9]+\.[0-9]+|commit [0-9a-f]{7,40})" "$FILE" \
  || { echo "$FILE header is missing a pinned ref — expected 'tag vX.Y.Z' or 'commit <sha>'" >&2; exit 1; }

echo "ok: $FILE has a well-formed vendoring header"

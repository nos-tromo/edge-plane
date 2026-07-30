#!/usr/bin/env bash
# Verifies landing/tokens.css still carries the vendoring header this repo
# requires: a canonical-source line and a pinned commit/tag. Same spirit as
# the scripts/bundle-lib.sh drift-check, but local instead of a live fetch
# against nos-tromo/infra-ui — that repo hasn't cut a release tag for this
# artifact, so there is no stable ref CI could pin a network fetch to.
# Re-vendoring (pulling a fresh copy and updating the pinned ref) is a
# documented manual step — see landing/tokens.css's own header.
set -euo pipefail

FILE="landing/tokens.css"

[[ -f "$FILE" ]] || { echo "missing $FILE" >&2; exit 1; }

grep -q "Vendored verbatim from nos-tromo/infra-ui" "$FILE" \
  || { echo "$FILE is missing its vendoring header (canonical source + pinned ref) — never hand-edit it without one" >&2; exit 1; }

grep -qE "commit [0-9a-f]{7,40}" "$FILE" \
  || { echo "$FILE header is missing a pinned commit SHA (or tag, once infra-ui releases one)" >&2; exit 1; }

echo "ok: $FILE has a well-formed vendoring header"

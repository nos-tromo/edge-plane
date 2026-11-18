#!/usr/bin/env bash
# Verifies every app upstream in caddy/Caddyfile carries its own edge secret.
# Each *_EDGE_SECRET is set to a different probe value, the Caddyfile is
# adapted to JSON by the pinned Caddy image (no network, nothing started),
# and every reverse_proxy handler must send exactly its own probe as
# X-Edge-Secret: a copy-pasted route that names a neighbour's variable sends
# the wrong secret, so that app's backend answers 401 to everyone.
#
# Not checked: the authelia:9091 handlers (`handle @auth` and the
# forward_auth that `import authed` expands to). They carry no edge secret.
#
# Adding an upstream means adding its row to UPSTREAMS below; a routed
# upstream that has no row fails the check.
set -euo pipefail

cd "$(dirname "$0")/.."

# upstream, then the *_EDGE_SECRET variable (without the suffix) it must carry
UPSTREAMS=(
  "docint-frontend:8080 DOCINT"
  "nextext-frontend:8080 NEXTEXT"
  "translator-frontend:8080 TRANSLATOR"
  "ghostwriter-frontend:8080 GHOSTWRITER"
  "grafana:3000 GRAFANA"
  "grafana-audit:3000 AUDIT"
)

image=$(sed -n 's|^[[:space:]]*image:[[:space:]]*\(docker\.io/library/caddy:[^[:space:]]*\).*|\1|p' docker/compose.yaml | head -1)
[[ -n "$image" ]] || { echo "no caddy image found in docker/compose.yaml" >&2; exit 1; }

adapted=$(mktemp)
trap 'rm -f "$adapted"' EXIT

env_args=(-e EDGE_HOST=127.0.0.1)
expect_args=()
for row in "${UPSTREAMS[@]}"; do
  upstream=${row% *}
  name=${row#* }
  env_args+=(-e "${name}_EDGE_SECRET=probe-${name}")
  expect_args+=("${upstream}=probe-${name}")
done

docker run --rm "${env_args[@]}" \
  -v "$PWD/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$PWD/caddy/conf.d:/etc/caddy/conf.d:ro" \
  "$image" caddy adapt --config /etc/caddy/Caddyfile >"$adapted" 2>/dev/null \
  || { echo "caddy adapt failed" >&2; exit 1; }

python3 -I - "$adapted" "${expect_args[@]}" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    config = json.load(fh)
expected = dict(arg.split("=", 1) for arg in sys.argv[2:])

proxies = {}


def walk(node):
    if isinstance(node, dict):
        if node.get("handler") == "reverse_proxy":
            ops = node.get("headers", {}).get("request", {})
            sent = {name.lower(): values for name, values in ops.get("set", {}).items()}
            # An add, delete or replace of the header changes what the set
            # line sends (a delete leaves none at all), so any of them fails.
            changed = any(
                name.lower() == "x-edge-secret"
                for name in [*ops.get("add", {}), *ops.get("delete", []), *ops.get("replace", {})]
            )
            for upstream in node.get("upstreams", []):
                proxies.setdefault(upstream.get("dial"), []).append(
                    (sent.get("x-edge-secret"), changed)
                )
        for value in node.values():
            walk(value)
    elif isinstance(node, list):
        for value in node:
            walk(value)


walk(config.get("apps", {}))

failed = False
for upstream, probe in expected.items():
    for sent, changed in proxies.get(upstream) or [(None, False)]:
        if changed:
            print(f"FAIL: {upstream} adds, deletes or replaces X-Edge-Secret", file=sys.stderr)
            failed = True
        elif not sent:
            print(f"FAIL: {upstream} carries no secret", file=sys.stderr)
            failed = True
        elif sent != [probe]:
            print(f"FAIL: {upstream} carries the wrong secret", file=sys.stderr)
            failed = True
for upstream in sorted(set(proxies) - set(expected) - {"authelia:9091"}):
    print(f"FAIL: {upstream} is routed but has no row in this script", file=sys.stderr)
    failed = True
if failed:
    sys.exit(1)
print(f"ok: {len(expected)} upstreams, each with its own edge secret")
PY

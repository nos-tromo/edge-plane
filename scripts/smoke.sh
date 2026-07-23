#!/usr/bin/env bash
# End-to-end contract checks against a running `make up-dev` stack.
# Verifies, via the whoami header-echo upstream:
#   1. unauthenticated browser request -> redirect to the /auth portal
#   2. first-factor login succeeds
#   3. authenticated request carries X-Auth-User=<user> upstream
#   4. a client-forged X-Auth-User NEVER reaches the upstream
set -euo pipefail

BASE="${EDGE_SMOKE_BASE:-https://127.0.0.1}"
USER_NAME="jane.doe"
PASSWORD="insecure-dev-password"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
CURL=(curl -sk --connect-timeout 5)

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

# 1. Unauthenticated -> redirected to the portal.
code_loc=$("${CURL[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' \
  -H 'Accept: text/html' "$BASE/whoami/")
[[ "$code_loc" == 302\ *"/auth"* ]] \
  || fail "expected 302 -> /auth for unauthenticated request, got: $code_loc"
echo "ok: unauthenticated request redirects to portal"

# 2. First-factor login (session cookie into the jar).
login=$("${CURL[@]}" -c "$JAR" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$PASSWORD\"}" \
  "$BASE/auth/api/firstfactor")
[[ "$login" == "200" ]] || fail "login returned HTTP $login"
echo "ok: first-factor login"

# 3+4. Authenticated request WITH a forged identity header: the upstream
# must see X-Auth-User=$USER_NAME and must NOT see the forged value.
body=$("${CURL[@]}" -b "$JAR" -H 'X-Auth-User: mallory' "$BASE/whoami/")
grep -qi "^X-Auth-User: $USER_NAME" <<<"$body" \
  || fail "upstream did not receive X-Auth-User=$USER_NAME:
$body"
grep -qi "mallory" <<<"$body" && fail "forged X-Auth-User reached the upstream:
$body"
echo "ok: X-Auth-User injected; forged header stripped"

# Landing page reachable with the session.
landing=$("${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/")
[[ "$landing" == "200" ]] || fail "landing page returned HTTP $landing"
echo "ok: landing page"

echo "SMOKE PASS"

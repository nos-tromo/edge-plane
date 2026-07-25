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

# Runs a curl invocation, failing with a labeled SMOKE FAIL message (instead
# of a bare `set -e` abort) if curl itself errors out (e.g. connection
# refused, exit 7, or a timeout, exit 28). On success, echoes curl's stdout.
run_curl() {
  local desc="$1"
  shift
  local out rc
  out=$("${CURL[@]}" "$@") && rc=0 || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fail "curl $desc failed (exit $rc)"
  fi
  printf '%s' "$out"
}

# 1. Unauthenticated -> redirected to the portal.
code_loc=$(run_curl "unauthenticated request" -o /dev/null -w '%{http_code} %{redirect_url}' \
  -H 'Accept: text/html' "$BASE/whoami/")
[[ "$code_loc" == 302\ *"/auth"* ]] \
  || fail "expected 302 -> /auth for unauthenticated request, got: $code_loc"
echo "ok: unauthenticated request redirects to portal"

# 1b. The portal URL we were redirected to must itself load — bare /auth
# included; a matcher gap here 404s the login flow after first factor.
portal_url=${code_loc#* }
portal=$(run_curl "portal page" -o /dev/null -w '%{http_code} %{content_type}' -H 'Accept: text/html' "$portal_url")
[[ "$portal" == 200\ text/html* ]] || fail "portal page did not load: $portal"
echo "ok: portal page loads ($portal_url)"

# 2. First-factor login (session cookie into the jar).
login=$(run_curl "first-factor login" -c "$JAR" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$PASSWORD\"}" \
  "$BASE/auth/api/firstfactor")
[[ "$login" == "200" ]] || fail "login returned HTTP $login"
echo "ok: first-factor login"

# 3+4. Authenticated request WITH forged identity headers: the upstream
# must see the gateway-injected X-Auth-User/X-Auth-Groups values and
# must NOT see the forged ones.
body=$(run_curl "authenticated whoami request" -b "$JAR" \
  -H 'X-Auth-User: mallory' -H 'X-Auth-Groups: admins' "$BASE/whoami/")
grep -qi "^X-Auth-User: $USER_NAME" <<<"$body" \
  || fail "upstream did not receive X-Auth-User=$USER_NAME:
$body"
grep -qi "^X-Auth-Groups: users" <<<"$body" \
  || fail "upstream did not receive X-Auth-Groups=users:
$body"
grep -qi "mallory" <<<"$body" && fail "forged X-Auth-User reached the upstream:
$body"
grep -qi "^X-Auth-Groups:.*admins" <<<"$body" && fail "forged X-Auth-Groups reached the upstream:
$body"
echo "ok: X-Auth-User + X-Auth-Groups injected; forged headers stripped"

# Landing page reachable with the session.
landing=$(run_curl "landing page request" -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/")
[[ "$landing" == "200" ]] || fail "landing page returned HTTP $landing"
echo "ok: landing page"

echo "SMOKE PASS"

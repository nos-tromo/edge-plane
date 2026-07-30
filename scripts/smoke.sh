#!/usr/bin/env bash
# End-to-end contract checks against a running `make up-dev` stack.
# Verifies, via the whoami header-echo upstream:
#   1. unauthenticated browser request -> redirect to the /auth portal
#   2. first-factor login succeeds
#   3. authenticated request carries X-Auth-User, X-Auth-Groups, and
#      X-Auth-Name upstream
#   4. client-forged X-Auth-User, X-Auth-Groups, and X-Auth-Name headers
#      NEVER reach the upstream
set -euo pipefail

BASE="${EDGE_SMOKE_BASE:-https://127.0.0.1}"
USER_NAME="jane.doe"
PASSWORD="insecure-dev-password"
DISPLAY_NAME="Jane Doe"
# Prefer the live dev users.yml's displayname (falls back to the template
# convention above if users.yml isn't present or doesn't match).
if [[ -f authelia/users.yml ]]; then
  live_name=$(awk '/^  jane\.doe:/{f=1;next} f&&/^  [a-zA-Z]/{f=0} f&&/displayname:/{match($0,/"[^"]*"/); print substr($0,RSTART+1,RLENGTH-2); exit}' authelia/users.yml)
  [[ -n "$live_name" ]] && DISPLAY_NAME="$live_name"
fi
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
# must see the gateway-injected X-Auth-User/X-Auth-Groups/X-Auth-Name
# values and must NOT see the forged ones.
body=$(run_curl "authenticated whoami request" -b "$JAR" \
  -H 'X-Auth-User: mallory' -H 'X-Auth-Groups: admins' \
  -H 'X-Auth-Name: Mallory Mallet' "$BASE/whoami/")
grep -qi "^X-Auth-User: $USER_NAME" <<<"$body" \
  || fail "upstream did not receive X-Auth-User=$USER_NAME:
$body"
grep -qi "^X-Auth-Groups: users" <<<"$body" \
  || fail "upstream did not receive X-Auth-Groups=users:
$body"
grep -qi "^X-Auth-Name: $DISPLAY_NAME" <<<"$body" \
  || fail "upstream did not receive X-Auth-Name=$DISPLAY_NAME:
$body"
grep -qi "mallory" <<<"$body" && fail "forged X-Auth-User reached the upstream:
$body"
grep -qi "^X-Auth-Groups:.*admins" <<<"$body" && fail "forged X-Auth-Groups reached the upstream:
$body"
grep -qi "Mallory Mallet" <<<"$body" && fail "forged X-Auth-Name reached the upstream:
$body"
echo "ok: X-Auth-User + X-Auth-Groups + X-Auth-Name injected; forged headers stripped"

# Portal reachable with the session, and actually the portal: the rendered
# page must contain the app grid and the status-probe script.
landing_body=$(run_curl "landing page request" -b "$JAR" "$BASE/")
grep -q 'id="app-grid"' <<<"$landing_body" \
  || fail "landing page is missing the app grid"
grep -q 'status-probe' <<<"$landing_body" \
  || fail "landing page is missing the status probe script"
echo "ok: portal page (app grid + status probe)"

# Code-viewer page: auth-gated, and no path under it serves the raw
# notification file (the rewrite pins everything to the template page).
ac_unauth=$(run_curl "unauthenticated auth-code request" -o /dev/null -w '%{http_code}' \
  -H 'Accept: text/html' "$BASE/auth-code")
[[ "$ac_unauth" == "302" ]] || fail "expected 302 for unauthenticated /auth-code, got: $ac_unauth"
ac_body=$(run_curl "auth-code raw-file probe" -b "$JAR" "$BASE/auth-code/notify/notification.txt")
grep -q "<title>" <<<"$ac_body" \
  || fail "/auth-code/notify/notification.txt did not render the viewer page:
$ac_body"
grep -qE "<title>(Verification code|Bestätigungscode)</title>" <<<"$ac_body" \
  || fail "/auth-code/notify/notification.txt did not render the viewer's title:
$ac_body"
grep -q "^Date:" <<<"$ac_body" \
  && fail "/auth-code/notify/notification.txt leaked the raw notification dump:
$ac_body"
echo "ok: auth-code gated and raw file unreachable"

# Password self-service API cycle: guards the undocumented endpoints the
# portal form depends on. Changes to a temp password and back; on a
# mid-cycle failure the dev user may be left on $TMP_PW (echoed below).
TMP_PW="smoke-temp-password"
elev=$(run_curl "elevation start" -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/auth/api/user/session/elevation")
[[ "$elev" == "200" ]] || fail "elevation start returned HTTP $elev"
otc=""
for _ in 1 2 3 4 5; do
  otc=$(run_curl "auth-code fetch" -b "$JAR" "$BASE/auth-code" \
    | sed -n 's/.*id="otc"[^>]*>\([A-Z0-9]*\)<.*/\1/p')
  [[ -n "$otc" ]] && break
  sleep 1
done
[[ -n "$otc" ]] || fail "no OTC marker surfaced on /auth-code"
redeem=$(run_curl "elevation redeem" -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
  -X PUT -H 'Content-Type: application/json' -d "{\"otc\":\"$otc\"}" \
  "$BASE/auth/api/user/session/elevation")
[[ "$redeem" == "200" ]] || fail "elevation redeem returned HTTP $redeem"
chg=$(run_curl "password change" -b "$JAR" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"old_password\":\"$PASSWORD\",\"new_password\":\"$TMP_PW\"}" \
  "$BASE/auth/api/change-password")
[[ "$chg" == "200" ]] || fail "password change returned HTTP $chg"
JAR2="$(mktemp)"
relogin=$(run_curl "temp-password login" -c "$JAR2" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$TMP_PW\"}" "$BASE/auth/api/firstfactor")
rm -f "$JAR2"
[[ "$relogin" == "200" ]] || fail "login with temp password failed (HTTP $relogin) — user may be on $TMP_PW"
chback=$(run_curl "password revert" -b "$JAR" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"old_password\":\"$TMP_PW\",\"new_password\":\"$PASSWORD\"}" \
  "$BASE/auth/api/change-password")
[[ "$chback" == "200" ]] || fail "password revert returned HTTP $chback — user is on $TMP_PW"
echo "ok: password self-service API cycle (elevation, change, revert)"

echo "SMOKE PASS"

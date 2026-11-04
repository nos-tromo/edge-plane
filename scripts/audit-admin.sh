#!/usr/bin/env bash
# Run an account change and record it in the audit trail (docs/audit.md).
#
#   COMPOSE="docker compose --env-file .env -f docker/compose.yaml" \
#     scripts/audit-admin.sh <operation> <account> [key=value ...] -- <command ...>
#
# 1. Refuses to start unless the auth-audit container can write its audit
#    stream: no account changes without its record.
# 2. Runs the change.
# 3. Writes one admin event with `docker compose exec` into auth-audit, so it
#    lands in that container's log: outcome ok when the change exited 0,
#    otherwise error (the change may have been applied in part). The operator
#    is the sudo user, or the login user without sudo.
#
# Exits with the change's status, or 1 when the event could not be written.
# The key=value criteria are recorded verbatim — never pass a secret.
set -euo pipefail

usage() {
  echo "usage: COMPOSE=<docker compose command> $0 <operation> <account> [key=value ...] -- <command ...>" >&2
  exit 2
}

[[ $# -ge 4 ]] || usage
operation=$1
account=$2
shift 2
criteria=()
while [[ $# -gt 0 && $1 != "--" ]]; do
  criteria+=("$1")
  shift
done
[[ $# -ge 2 ]] || usage
shift

read -r -a compose <<<"${COMPOSE:?COMPOSE must hold the docker compose command}"
operator="${SUDO_USER:-$(id -un)}"
audit=("${compose[@]}" exec -T -e "AUDIT_CLI_USER=$operator" auth-audit python /app/edge_audit.py)

if ! "${audit[@]}" check; then
  echo "auth-audit cannot record the change: start the stack first (make up). Nothing was changed." >&2
  exit 1
fi

# An interrupted change is still recorded, as error.
status=0
trap 'status=130' INT
"$@" || status=$?
trap - INT

outcome=ok
[[ $status -eq 0 ]] || outcome=error
if ! "${audit[@]}" admin --outcome "$outcome" "$operation" "$account" ${criteria[@]+"${criteria[@]}"}; then
  echo "The change ran (exit $status), but its audit event could not be written: record it by other means." >&2
  exit 1
fi
exit "$status"

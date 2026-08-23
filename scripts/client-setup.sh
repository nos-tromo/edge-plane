#!/usr/bin/env bash
# One-shot client provisioning for an airgapped LAN machine that must
# reach the edge gateway. Run ON THE CLIENT, as root, with the exported
# CA root (`make ca-export` on the gateway) copied alongside:
#
#   sudo ./client-setup.sh <edge-host> <gateway-ip> <path/to/edge-ca-root.crt>
#
# It performs, idempotently:
#   1. /etc/hosts entry mapping <edge-host> -> <gateway-ip>
#      (no LAN DNS on an airgapped network; see docs/tls-runbook.md,
#      "EDGE_HOST caveat")
#   2. system trust store install (update-ca-certificates)
#   3. Firefox trust via the enterprise policy file
#      /etc/firefox/policies/policies.json (read by both the deb and the
#      snap build; avoids needing certutil/libnss3-tools, which an
#      airgapped client cannot apt-install)
#
# Only needed for the internal-CA shape (EDGE_TLS unset). Once the
# gateway serves an org-issued certificate the clients already trust,
# steps 2-3 become unnecessary; step 1 still is, unless LAN DNS exists.
set -euo pipefail

CERT_NAME="edge-ca-root.crt"
STORE_PATH="/usr/local/share/ca-certificates/${CERT_NAME}"
POLICY_DIR="/etc/firefox/policies"
POLICY_FILE="${POLICY_DIR}/policies.json"

usage() {
  echo "usage: sudo $0 <edge-host> <gateway-ip> <path/to/${CERT_NAME}>" >&2
  exit 2
}

[[ $# -eq 3 ]] || usage
EDGE_HOST="$1"
GATEWAY_IP="$2"
CERT_SRC="$3"

[[ $(id -u) -eq 0 ]] || { echo "error: must run as root (sudo)" >&2; exit 1; }
[[ -f "$CERT_SRC" ]] || { echo "error: certificate not found: $CERT_SRC" >&2; exit 1; }
[[ "$EDGE_HOST" == *.* ]] || { echo "error: <edge-host> must be a dotted hostname (got '$EDGE_HOST')" >&2; exit 1; }
openssl x509 -in "$CERT_SRC" -noout 2>/dev/null \
  || { echo "error: $CERT_SRC is not a PEM certificate" >&2; exit 1; }

# --- 1. /etc/hosts ---------------------------------------------------------
# Replace any prior line for this hostname so re-runs with a new IP win.
host_re="${EDGE_HOST//./\\.}"
if grep -qE "[[:space:]]${host_re}([[:space:]]|\$)" /etc/hosts; then
  sed -i -E "/[[:space:]]${host_re}([[:space:]]|\$)/d" /etc/hosts
fi
printf '%s\t%s\n' "$GATEWAY_IP" "$EDGE_HOST" >> /etc/hosts
getent hosts "$EDGE_HOST" >/dev/null \
  || { echo "error: $EDGE_HOST still does not resolve after hosts edit" >&2; exit 1; }
echo "ok: $EDGE_HOST -> $GATEWAY_IP in /etc/hosts"

# --- 2. system trust store -------------------------------------------------
install -m 0644 "$CERT_SRC" "$STORE_PATH"
update-ca-certificates >/dev/null
echo "ok: CA root installed in system trust store ($STORE_PATH)"

# --- 3. Firefox (enterprise policy) ---------------------------------------
if [[ -f "$POLICY_FILE" ]]; then
  if grep -q "$STORE_PATH" "$POLICY_FILE"; then
    echo "ok: Firefox policy already references $STORE_PATH"
  else
    # Don't risk clobbering someone's existing policies; merging JSON
    # without jq (airgap: may not be installed) isn't worth the fragility.
    echo "warning: $POLICY_FILE exists but does not reference the CA." >&2
    echo "  Merge this into its \"policies\" object manually:" >&2
    echo "    \"Certificates\": { \"Install\": [\"$STORE_PATH\"] }" >&2
  fi
else
  mkdir -p "$POLICY_DIR"
  cat > "$POLICY_FILE" <<EOF
{
  "policies": {
    "Certificates": {
      "Install": ["$STORE_PATH"]
    }
  }
}
EOF
  chmod 0644 "$POLICY_FILE"
  echo "ok: Firefox policy written ($POLICY_FILE)"
fi

echo
echo "Done. Restart Firefox, then open https://${EDGE_HOST}/"

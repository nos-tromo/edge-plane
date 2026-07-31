#!/usr/bin/env bash
# Fails if the portal's hand-written CSS carries a literal dimensional value.
#
# The portal is unprocessed static HTML — nothing compiles it, so nothing
# stops a raw `font-size: .9rem` reappearing. It consumes @infra/ui's exported
# scale via landing/tokens.css instead; this check is what keeps that true.
#
# Scans inline style= attributes as well as the <style> block: the auth-code
# page's OTC size lived in an attribute, exactly where a block-only check
# would miss it.
#
# Not guarded: spacing (per-element padding is legitimately bespoke) and
# letter-spacing (no token scale). border-radius: 50% passes because it is a
# circle, not a scale step — the pattern below only matches rem values.
set -euo pipefail

FILES=(landing/index.html authcode/index.html)
status=0

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
  while IFS= read -r hit; do
    echo "$f:$hit" >&2
    status=1
  done < <(grep -nE '(font-size|border-radius)[[:space:]]*:[[:space:]]*[0-9.]+rem' "$f" || true)
done

if (( status )); then
  cat >&2 <<'MSG'

Literal dimensional values found above. The portal consumes @infra/ui's
exported scale — use var(--text-xs|sm|base|lg|xl|2xl) or
var(--radius-md|lg) instead of a raw rem value.
MSG
  exit 1
fi

echo "ok: no literal font-size/border-radius values in the portal"

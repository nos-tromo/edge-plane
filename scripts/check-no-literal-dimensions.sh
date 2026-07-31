#!/usr/bin/env bash
# Fails if the portal's hand-written CSS sets font-size or border-radius to
# anything other than a token.
#
# The portal is unprocessed static HTML — nothing compiles it, so nothing
# stops a raw `font-size: .9rem` (or `14px`, `calc(1rem * 0.9)`, `90%`, ...)
# reappearing. It consumes @infra/ui's exported scale via landing/tokens.css
# instead; this check is what keeps that true. The rule is a whitelist, not a
# blacklist of units: every font-size and border-radius declaration must be
# var(...), one of the CSS-wide keywords (inherit/initial/unset), or the
# border-radius: 50% circle exception on .dot.
#
# Scans inline style= attributes as well as the <style> block: the auth-code
# page's OTC size lived in an attribute, exactly where a block-only check
# would miss it.
#
# Matches per-occurrence, not per-line: a single line can carry both a
# compliant and a non-compliant declaration (e.g. `font-size: var(--text-sm);
# border-radius: 7px;`), and a line-based filter would wrongly clear the
# whole line.
#
# Not guarded: spacing (per-element padding is legitimately bespoke) and
# letter-spacing (no token scale).
set -euo pipefail

FILES=(landing/index.html authcode/index.html)
status=0

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
  while IFS= read -r hit; do
    echo "$f:$hit" >&2
    status=1
  done < <(grep -onE '(font-size|border-radius)[[:space:]]*:[[:space:]]*[^;}]*' "$f" \
      | grep -vE ':[[:space:]]*(var\(|inherit|initial|unset)' \
      | grep -vE 'border-radius[[:space:]]*:[[:space:]]*50%[[:space:]]*$' \
      || true)
done

if (( status )); then
  cat >&2 <<'MSG'

Non-token dimensional values found above. font-size and border-radius must
always reference @infra/ui's exported scale — use
var(--text-xs|sm|base|lg|xl|2xl) or var(--radius-md|lg) — not a literal
value. The only exception is border-radius: 50% (a circle, not a scale step).
MSG
  exit 1
fi

echo "ok: no literal font-size/border-radius values in the portal"

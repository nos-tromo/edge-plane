#!/usr/bin/env bash
# Fails if the portal's hand-written CSS sets font-size, the font shorthand,
# or any border-radius (including longhands) to anything other than a
# recognised token.
#
# The portal is unprocessed static HTML — nothing compiles it, so nothing
# stops a raw `font-size: .9rem` (or `14px`, `calc(1rem * 0.9)`, `90%`, ...)
# reappearing. It consumes @infra/ui's exported scale via landing/tokens.css
# instead; this check is what keeps that true.
#
# The rule is membership, not syntax: a declaration must resolve to one of
# the eight tokens landing/tokens.css actually exports (--text-xs/sm/base/
# lg/xl/2xl, --radius-md/lg), a CSS-wide keyword, or the border-radius: 50%
# circle exception below — not merely "starts with var(...)". An earlier
# version of this check accepted any var(...) call, so a typo'd or
# nonexistent token name (var(--text-md), var(--radius-huge)) passed CI
# while the declaration silently dropped at computed-value time and the
# element inherited its parent's size. A var() fallback
# (var(--text-sm, 13px)) is rejected the same way, since the literal
# fallback is exactly the kind of value this check exists to catch.
#
# The property side covers three things a plain `font-size|border-radius`
# match misses:
#   - the `font` shorthand (`font: 13px/1.5 serif`) — this file already
#     uses `font: inherit` twice, so the shorthand is an established idiom
#     here, and a future edit that collapses two declarations into a
#     literal `font: ...` would slip straight past a check that only knows
#     `font-size`.
#   - every border-radius longhand — physical (border-top-left-radius, ...)
#     and logical (border-start-start-radius, ...) — not just the
#     `border-radius` shorthand.
#   - case: CSS property names are case-insensitive; the match is too
#     (grep -i).
#
# The border-radius: 50% exception is global — any selector may use it to
# draw a circle — not scoped to any one class; there is nothing
# selector-aware in a regex-based check, so scoping it further would just
# be a false sense of precision.
#
# CSS-wide keywords accepted alongside tokens: inherit, initial, unset,
# revert, revert-layer — that is the complete current set.
#
# Scans inline style= attributes as well as the <style> block: the
# auth-code page's OTC size lived in an attribute, exactly where a
# block-only check would miss it.
#
# Matches per-occurrence, not per-line: a single line can carry both a
# compliant and a non-compliant declaration (e.g. `font-size: var(--text-sm);
# border-radius: 7px;`), and a line-based filter would wrongly clear the
# whole line. Known limitation: a declaration's value is still evaluated
# per-line, so a compliant `font-size:` whose value wraps onto the next
# line is flagged as if the property had no value — keep such declarations
# on one line rather than reflowing them.
#
# Not guarded: spacing (--spacing is deliberately unexported — there is no
# token to check membership against, only an arithmetic "multiple of
# .25rem" rule, a different kind of invariant) and letter-spacing (no
# token scale). Spacing was hand-snapped to the .25rem grid once as part
# of the dimensional-tokens migration but is not enforced, so — unlike
# font-size/border-radius — it can drift back on a future hand-edit.
#
# Discovers portal pages instead of hardcoding them, so a third page added
# under landing/ or authcode/ can't end up silently unguarded.
set -euo pipefail

PROP='(^|[{;[:space:]])(font|font-size|[a-z-]*border[a-z-]*-radius)[[:space:]]*:[[:space:]]*[^;}]*'
ALLOW=':[[:space:]]*(var\((--text-(xs|sm|base|lg|xl|2xl)|--radius-(md|lg))\)[[:space:]]*$|inherit|initial|unset|revert|revert-layer)'
CIRCLE='border[a-z-]*-radius[[:space:]]*:[[:space:]]*50%[[:space:]]*$'

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(find landing authcode -name '*.html' | sort)
if (( ${#FILES[@]} == 0 )); then
  echo "no portal *.html files found under landing/ or authcode/" >&2
  exit 1
fi

status=0

for f in "${FILES[@]}"; do
  while IFS= read -r hit; do
    echo "$f:$hit" >&2
    status=1
  done < <(grep -onEi "$PROP" "$f" \
      | grep -viE "$ALLOW" \
      | grep -viE "$CIRCLE" \
      || true)
done

if (( status )); then
  cat >&2 <<'MSG'

Non-token dimensional values found above. font-size, the font shorthand, and
every border-radius property (including longhands) must always resolve to
one of @infra/ui's exported tokens — var(--text-xs|sm|base|lg|xl|2xl) or
var(--radius-md|lg) — not a literal value, and not a var() fallback. The
only exception is border-radius: 50% (a circle, not a scale step).
MSG
  exit 1
fi

echo "ok: no literal font-size/border-radius values in the portal"

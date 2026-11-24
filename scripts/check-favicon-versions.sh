#!/usr/bin/env bash
# Verifies every portal page links the favicon set versioned by content:
# href="/<icon>?v=<first 8 hex digits of the file's SHA-256 in landing/>".
# A browser keeps a favicon in its own store, keyed by the icon's URL, and
# ignores no-cache for it, so a redrawn icon has to arrive under a new URL.
# After redrawing an icon, put its new digits into every page's links.
#
# Not covered: /favicon.ico, which browsers and Authelia's login page ask
# for on their own, so no link can version it.
set -euo pipefail

cd "$(dirname "$0")/.."

PAGES=(landing/index.html landing/info.html authcode/index.html)
ICONS=(favicon-32.png favicon.svg apple-touch-icon.png)

status=0
for icon in "${ICONS[@]}"; do
  version=$(shasum -a 256 "landing/$icon" | cut -c1-8)
  expected="href=\"/${icon}?v=${version}\""
  for page in "${PAGES[@]}"; do
    links=$(grep -oE "href=\"/${icon//./\\.}(\\?[^\"]*)?\"" "$page" || true)
    if [[ -z "$links" ]]; then
      echo "$page: no link to /$icon" >&2
      status=1
      continue
    fi
    while IFS= read -r link; do
      [[ "$link" == "$expected" ]] || { echo "$page: $link, expected $expected" >&2; status=1; }
    done <<<"$links"
  done
done

[[ $status -eq 0 ]] && echo "ok: every portal page links the favicon set versioned by content"
exit "$status"

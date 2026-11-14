<!--
Smoke-test fixture for /info/smoke (scripts/smoke.sh); not for production,
and deploy does not ship it.
-->
<!-- smoke-hidden-comment: scripts/smoke.sh asserts this comment never reaches the page. -->
# smoke-info

**smoke-info-page**: test fixture for `make up-dev` / `make smoke`, not for production.

This literal must stay unevaluated: {{env "WHOAMI_EDGE_SECRET"}}

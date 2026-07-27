# edge-plane: X-Auth-Groups contract widening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Forward Authelia's `Remote-Groups` to upstreams as a new trusted header `X-Auth-Groups`, spoof-proof, so docint (and later apps) can grant admin capabilities from the Authelia `admins` group.

**Architecture:** Two snippet edits in `caddy/Caddyfile` (strip the client-supplied header; copy Authelia's `Remote-Groups` into `X-Auth-Groups`), a synthetic group on the template user, and extended smoke assertions. Pure widening — upstreams that ignore the header are unaffected.

**Tech Stack:** Caddy 2 Caddyfile, bash smoke script, Docker Compose. No Python, no test framework — the test cycle is `caddy validate` + `make up-dev` + `scripts/smoke.sh`.

**Spec:** `../docint/docs/specs/2026-07-25-admin-all-collections-design.md` (section 1). Repo runbook: `README.md`; repo rules: `CLAUDE.md`.

## Global Constraints

- Header name is exactly `X-Auth-Groups`; value is Authelia's comma-separated group list (`Remote-Groups`), copied verbatim.
- The gateway must strip client-supplied `X-Auth-Groups` on every request, before routing (same rule as `X-Auth-User`).
- Only synthetic identities in anything committed (template user `jane.doe`, group `users`) — never real data (CLAUDE.md hard rule).
- Working directory for all commands: the edge-plane repo root.
- This repo's CI runs the same smoke script; keep `scripts/smoke.sh` shellcheck-clean (CI runs shellcheck via the shared infra-validation workflow).

---

### Task 1: Contract widening + smoke coverage

**Files:**
- Modify: `caddy/Caddyfile` (the `strip_identity` snippet, lines ~17-24, and the `authed` snippet, lines ~30-38)
- Modify: `authelia/users.template.yml` (template user's `groups`)
- Modify: `scripts/smoke.sh` (extend step 3+4)

**Interfaces:**
- Produces: upstreams on `edge-net` receive `X-Auth-Groups: <comma-separated groups>` on every authenticated proxied request; client-supplied values never pass. docint's plan consumes exactly this header.

- [ ] **Step 1: Write the failing smoke assertions**

In `scripts/smoke.sh`, replace the step "3+4" block (the one that fetches `$BASE/whoami/` with a forged `X-Auth-User: mallory` and greps the body) with a version that also forges `X-Auth-Groups` and asserts the injected group value. The whoami upstream echoes request headers, so the body carries proof:

```bash
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
```

Note the forged group is `admins` while the template user's real group will be `users` — so a leak is unambiguous.

- [ ] **Step 2: Run the smoke to verify it fails**

Precondition: a running dev stack from current `main` behavior. If not already up:
`cp .env.example .env` (only if `.env` is missing), `cp authelia/users.template.yml authelia/users.yml` (only if missing), then `make up-dev` and wait for `make health` to report both services ready.

Run: `./scripts/smoke.sh`
Expected: `SMOKE FAIL: upstream did not receive X-Auth-Groups=users` — the gateway does not yet forward groups (and the user has no group).

- [ ] **Step 3: Give the template user a synthetic group**

In `authelia/users.template.yml`, change the template user's `groups: []` to:

```yaml
    groups:
      - users
```

Then refresh the local copy so the running stack picks it up: `cp authelia/users.template.yml authelia/users.yml` (dev/CI only — on a real deployment `users.yml` is operator-managed and must never be overwritten; this plan only ever runs against the dev stack).

- [ ] **Step 4: Widen the Caddyfile contract**

In `caddy/Caddyfile`:

a) `strip_identity` snippet — add one line so it reads:

```caddyfile
(strip_identity) {
	request_header -X-Auth-User
	request_header -X-Auth-Email
	request_header -X-Auth-Groups
	request_header -Remote-User
	request_header -Remote-Groups
	request_header -Remote-Email
	request_header -Remote-Name
}
```

(`-Remote-Groups` is already present; the new line is `-X-Auth-Groups`.)

b) `authed` snippet — add the copy rule:

```caddyfile
(authed) {
	forward_auth authelia:9091 {
		uri /api/authz/forward-auth
		copy_headers {
			Remote-User>X-Auth-User
			Remote-Email>X-Auth-Email
			Remote-Groups>X-Auth-Groups
		}
	}
}
```

- [ ] **Step 5: Validate the Caddyfile**

Run (image ref must match `docs/images.md`):

```bash
docker run --rm -e EDGE_HOST=127.0.0.1 \
  -v "$PWD/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$PWD/caddy/conf.d:/etc/caddy/conf.d:ro" \
  docker.io/library/caddy:2.11.4@sha256:844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9 \
  caddy validate --config /etc/caddy/Caddyfile
```

Expected: `Valid configuration`.

- [ ] **Step 6: Restart the dev stack and run the smoke to verify it passes**

Run:

```bash
docker compose --env-file .env -f docker/compose.yaml -f docker/compose.override.yaml up -d --force-recreate caddy authelia
```

(`--force-recreate` because both the Caddyfile and users.yml are read-only bind mounts; authelia must restart to reload users.) Wait for `make health` to report both ready, then:

Run: `./scripts/smoke.sh`
Expected: all `ok:` lines including `ok: X-Auth-User + X-Auth-Groups injected; forged headers stripped`, ending `SMOKE PASS`.

Also run: `shellcheck scripts/smoke.sh` — expected: no output.

- [ ] **Step 7: Commit**

```bash
git checkout -b feature/x-auth-groups
git add caddy/Caddyfile authelia/users.template.yml scripts/smoke.sh
git commit -m "feat: forward Authelia groups as X-Auth-Groups (strip + copy, smoke-verified)"
```

---

### Task 2: Document the contract + release bump

**Files:**
- Modify: `README.md` ("The trusted-header contract" section)
- Modify: `VERSION`

**Interfaces:**
- Consumes: the header behavior shipped in Task 1.
- Produces: an annotated release tag (minted by CI on merge) that deployment can promote before docint's feature lands.

- [ ] **Step 1: Document `X-Auth-Groups` in the README**

In `README.md`, section "The trusted-header contract": in flow step 1, add `X-Auth-Groups` to the list of headers Caddy unconditionally strips; in flow step 3, after the sentence about `X-Auth-Email`, add:

```markdown
The gateway likewise forwards **`X-Auth-Groups`** (from Authelia's
`Remote-Groups`, comma-separated) so upstreams can make group-based
authorization decisions — e.g. docint grants members of the `admins`
group visibility into all users' collections. Groups are defined per
user in `authelia/users.yml`.
```

- [ ] **Step 2: Bump the version**

`VERSION` holds a one-line semver. This is a backward-compatible feature: bump the **minor** version (e.g. a current `1.2.x` becomes `1.3.0` — read the file for the actual value). The release-tag workflow mints the annotated tag on merge; do not create tags by hand.

- [ ] **Step 3: Re-run the full smoke as the final gate**

Run: `./scripts/smoke.sh` (stack still up from Task 1)
Expected: `SMOKE PASS`.

- [ ] **Step 4: Commit**

```bash
git add README.md VERSION
git commit -m "docs: document X-Auth-Groups in the trusted-header contract; bump version"
```

Then open a PR (`feature/x-auth-groups` → `main`) per the federation's GitHub Flow. Do not push without the user's go-ahead.

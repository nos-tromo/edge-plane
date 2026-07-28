# Rollout-Readiness Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship session tuning, password self-service, and the portal upgrade per `docs/2026-07-28-rollout-readiness-design.md` as one edge-plane release (v0.3.0).

**Architecture:** All changes live in edge-plane: Authelia config gains explicit session lifetimes and password-change/reset posture; the Caddy-templated static landing page becomes an app portal (tiles, live status via same-origin fetch, user section, support tile); the smoke script gains a portal assertion. No new containers, no build step.

**Tech Stack:** Authelia 4.39.20 (file backend), Caddy 2.11.4 (`templates` directive, Go text/template), vanilla HTML/CSS/JS, bash smoke script.

## Global Constraints

- Repo: work inside `edge-plane/` on branch `feature/rollout-readiness`; bespoke Makefile (no `make verify`).
- Airgap: no external fetches at runtime — no CDN links, no webfonts, no telemetry.
- Confidentiality: no real user data, contact data, or local dev filepaths in committed files; support contact comes only from env `EDGE_SUPPORT_CONTACT`.
- De-branding: no "nos-tromo" or "federation" strings in the portal page.
- i18n: every user-visible portal string has en + de variants switched by `RESPONSE_LANGUAGE` (existing pattern in `landing/index.html`).
- Session values (from spec, verbatim): `expiration: 12h`, `inactivity: 4h`, `remember_me: 2M`.
- The strip → auth → inject header contract must stay intact: `scripts/smoke.sh` must pass unmodified in its steps 1–4.
- Validation commands used throughout (run from repo root):

```bash
# Compose validation (CI-equivalent):
docker compose --env-file .env -f docker/compose.yaml config --quiet

# Authelia config validation (template filter + dummy secrets):
docker run --rm \
  -e EDGE_HOST=127.0.0.1 -e X_AUTHELIA_CONFIG_FILTERS=template \
  -e AUTHELIA_SESSION_SECRET=validate-only \
  -e AUTHELIA_STORAGE_ENCRYPTION_KEY=validate-only-0123456789abcdef \
  -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=validate-only \
  -v "$PWD/authelia/configuration.yml:/config/configuration.yml:ro" \
  -v "$PWD/authelia/users.template.yml:/config/users.yml:ro" \
  docker.io/authelia/authelia:4.39.20@sha256:1b363e9279e742397966333f364e0876ae02bf5c876de73e83af6d48c57ff51b \
  authelia validate-config --config /config/configuration.yml
```

---

### Task 1: Session lifetimes

**Files:**
- Modify: `authelia/configuration.yml` (session block, lines 35–41)

**Interfaces:**
- Produces: session behaviour only; no downstream code depends on it. Task 5 verifies it manually.

- [ ] **Step 1: Edit the session block**

Replace the current session block:

```yaml
session:
  name: authelia_session
  same_site: lax
  # Defaults would be 1h expiration / 5min inactivity — the cause of the
  # pre-v0.3 frequent-logout complaints. Working-day session, meal-proof
  # inactivity window, vacation-proof remember-me.
  expiration: 12h
  inactivity: 4h
  remember_me: 2M
  cookies:
    - domain: '{{ env "EDGE_HOST" }}'
      authelia_url: 'https://{{ env "EDGE_HOST" }}/auth'
      default_redirection_url: 'https://{{ env "EDGE_HOST" }}/'
```

- [ ] **Step 2: Validate**

Run both validation commands from Global Constraints.
Expected: compose command silent, exit 0; authelia command prints "Configuration parsed and loaded successfully" (warnings about the file users db are acceptable, errors are not).

- [ ] **Step 3: Commit**

```bash
git add authelia/configuration.yml
git commit -m "feat: explicit session lifetimes (12h/4h, remember-me 2M)"
```

---

### Task 2: Password self-service posture

**Files:**
- Modify: `authelia/configuration.yml` (authentication_backend block, lines 12–14)
- Modify: `README.md` (new "User accounts" section, after the secrets-provisioning section)

**Interfaces:**
- Produces: the Authelia settings UI at `/auth/settings` with password change enabled and password reset removed. Task 3's portal links to `/auth/settings`; Task 5 verifies the flow manually.

- [ ] **Step 1: Edit the authentication_backend block**

```yaml
authentication_backend:
  file:
    path: /config/users.yml
  # Self-service password change via the settings UI (/auth/settings).
  password_change:
    disable: false
  # Reset needs the notifier; ours is the filesystem notifier (airgap), so
  # the built-in "forgot password" flow would dead-end in a file only
  # operators read. Resets are admin-mediated instead (README §User accounts).
  password_reset:
    disable: true
```

- [ ] **Step 2: Validate**

Run both validation commands from Global Constraints. Expected: both pass. If validation rejects `password_change` or `password_reset` placement under `authentication_backend`, stop and check `https://www.authelia.com/configuration/first-factor/introduction/` for the 4.39 schema rather than guessing.

- [ ] **Step 3: Add README "User accounts" section**

Insert after the secrets/users provisioning section:

```markdown
## User accounts

- **Provisioning** is operator-side: `make user` hashes a password; add the
  entry to `authelia/users.yml` (see `authelia/users.template.yml`).
- **Password change** is self-service: users open the portal's
  *Account settings* link (`/auth/settings`) and change their password there.
- **Password reset** ("forgotten password") is admin-mediated by design: the
  filesystem notifier means Authelia's built-in reset flow cannot reach
  users, so it is disabled (`password_reset.disable: true`). To reset,
  run `make user` and replace the user's hash in `authelia/users.yml`.
```

- [ ] **Step 4: Commit**

```bash
git add authelia/configuration.yml README.md
git commit -m "feat: enable self-service password change, disable dead-end reset flow"
```

---

### Task 3: Portal upgrade

**Files:**
- Modify: `landing/index.html` (full rewrite, content below)
- Modify: `docker/compose.yaml` (caddy `environment`, after `RESPONSE_LANGUAGE`)
- Modify: `.env.example` (new `EDGE_SUPPORT_CONTACT` entry)

**Interfaces:**
- Consumes: `/auth/settings` (Task 2), `/auth/logout` (existing), gateway app routes (existing Caddyfile).
- Produces: portal markers used by Task 4's smoke assertion: element `id="app-grid"` and script marker comment `/* status-probe */`. Theme key for the later infra-ui work: `localStorage["infra-ui-theme"]`, seeded to `"dark"` if unset.

- [ ] **Step 1: Add the env plumbing**

`docker/compose.yaml`, caddy `environment`, directly after the `RESPONSE_LANGUAGE` line:

```yaml
      # Optional support contact rendered on the portal's "report a problem"
      # tile (hidden when unset). Never commit a real value.
      EDGE_SUPPORT_CONTACT: ${EDGE_SUPPORT_CONTACT:-}
```

`.env.example`, after the `RESPONSE_LANGUAGE` block:

```bash
# Support contact shown on the portal's "report a problem" tile (e.g. an
# email address or room/phone). Unset -> tile is hidden.
# EDGE_SUPPORT_CONTACT=admin@example.invalid
```

- [ ] **Step 2: Rewrite `landing/index.html`**

Full replacement content:

```html
{{$de := eq (env "RESPONSE_LANGUAGE") "de"}}{{$support := env "EDGE_SUPPORT_CONTACT"}}<!doctype html>
<html lang="{{if $de}}de{{else}}en{{end}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Apps</title>
<style>
  :root {
    --bg: #0b0d10; --surface: #15181d; --border: #262b33;
    --text: #e6e8eb; --muted: #8b939e; --accent: #8ab4f8;
    --ok: #34c26b; --down: #e5534b; --neutral: #8b939e;
  }
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: var(--bg);
         color: var(--text); margin: 0; min-height: 100vh;
         display: flex; flex-direction: column; align-items: center; }
  main { width: min(64rem, 100% - 3rem); padding: 3rem 0; }
  h1 { font-size: 1.4rem; font-weight: 600; margin: 0 0 1.5rem; }
  #app-grid { display: grid; gap: 1rem; padding: 0; margin: 0;
              list-style: none;
              grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); }
  .tile { background: var(--surface); border: 1px solid var(--border);
          border-radius: .6rem; padding: 1rem 1.1rem; }
  .tile a.app { color: var(--accent); text-decoration: none;
                font-size: 1.1rem; font-weight: 600; }
  .tile a.app:hover { text-decoration: underline; }
  .tile p { color: var(--muted); font-size: .85rem; margin: .4rem 0 0; }
  .dot { display: inline-block; width: .55rem; height: .55rem;
         border-radius: 50%; margin-left: .5rem; background: var(--neutral); }
  .dot[data-state="online"] { background: var(--ok); }
  .dot[data-state="offline"] { background: var(--down); }
  section.user { margin-top: 2.5rem; border-top: 1px solid var(--border);
                 padding-top: 1.25rem; font-size: .9rem; color: var(--muted); }
  section.user a { color: var(--accent); text-decoration: none; }
  section.user a:hover { text-decoration: underline; }
  section.user .links { margin-top: .5rem; display: flex; gap: 1.25rem;
                        flex-wrap: wrap; }
</style>
</head>
<body>
<main>
  <h1>Apps</h1>
  <ul id="app-grid">
    <li class="tile"><a class="app" href="/chorus/">chorus</a><span class="dot" data-probe="/chorus/"></span>
      <p>{{if $de}}Analyse sozialer Netzwerke{{else}}Social-network analysis{{end}}</p></li>
    <li class="tile"><a class="app" href="/docint/">docint</a><span class="dot" data-probe="/docint/"></span>
      <p>{{if $de}}Dokumentenanalyse: Import, Suche, Chat{{else}}Document intelligence: ingestion, search, chat{{end}}</p></li>
    <li class="tile"><a class="app" href="/nextext/">Nextext</a><span class="dot" data-probe="/nextext/"></span>
      <p>{{if $de}}Transkription und Übersetzung von Audio/Video{{else}}Audio/video transcription and translation{{end}}</p></li>
    <li class="tile"><a class="app" href="/translator/">translator</a><span class="dot" data-probe="/translator/"></span>
      <p>{{if $de}}Textübersetzung{{else}}Text translation{{end}}</p></li>
    <li class="tile"><a class="app" href="/webui/">Open WebUI</a>
      <p>{{if $de}}Chat mit Sprachmodellen{{else}}Chat with language models{{end}}</p></li>
    <li class="tile"><a class="app" href="/grafana/">Grafana</a><span class="dot" data-probe="/grafana/"></span>
      <p>{{if $de}}Monitoring-Dashboards (nur Admins){{else}}Monitoring dashboards (admins only){{end}}</p></li>
    {{if $support}}<li class="tile"><span class="app">{{if $de}}Problem melden{{else}}Report a problem{{end}}</span>
      <p>{{if $de}}Wende dich an{{else}}Contact{{end}} {{$support | html}}</p></li>{{end}}
  </ul>
  <section class="user">
    <span>{{if $de}}Angemeldet als{{else}}Signed in as{{end}} <strong>{{.Req.Header.Get "X-Auth-User" | html}}</strong></span>
    <div class="links">
      <a href="/auth/settings">{{if $de}}Kontoeinstellungen (Passwort ändern){{else}}Account settings (change password){{end}}</a>
      <a href="/auth/logout">{{if $de}}Abmelden{{else}}Sign out{{end}}</a>
    </div>
    <p>{{if $de}}Passwort vergessen? Wende dich an die Administration.{{else}}Forgot your password? Contact your administrator.{{end}}</p>
  </section>
</main>
<script>
/* status-probe */
(function () {
  if (!localStorage.getItem('infra-ui-theme')) {
    localStorage.setItem('infra-ui-theme', 'dark');
  }
  function probe() {
    document.querySelectorAll('.dot[data-probe]').forEach(function (dot) {
      fetch(dot.dataset.probe, { method: 'HEAD', cache: 'no-store' })
        .then(function (res) {
          if (res.ok) { dot.dataset.state = 'online'; }
          else if (res.status === 403) { delete dot.dataset.state; } /* restricted, not down */
          else { dot.dataset.state = 'offline'; }
        })
        .catch(function () { dot.dataset.state = 'offline'; });
    });
  }
  probe();
  setInterval(probe, 60000);
})();
</script>
</body>
</html>
```

Notes locked in by the design: Open WebUI gets no probe (its `/webui` route is a cross-port redirect the browser cannot probe same-origin); a 403 on `/grafana/` renders the neutral dot (restricted ≠ offline); the file contains no working-title branding.

- [ ] **Step 3: Validate**

Run the compose validation command; additionally check the template renders without a Caddy error by bringing up dev and fetching the page:

```bash
make up-dev
sleep 5 && curl -sk https://127.0.0.1/ -o /dev/null -w '%{http_code}\n'
```

Expected: `302` (unauthenticated redirect — proves Caddy parsed the template site without 500). A `500` means a template syntax error: check `make logs S=caddy`.

- [ ] **Step 4: Commit**

```bash
git add landing/index.html docker/compose.yaml .env.example
git commit -m "feat: portal landing page — app tiles, live status, user section, support tile"
```

---

### Task 4: Smoke assertion for the portal

**Files:**
- Modify: `scripts/smoke.sh` (extend the existing landing-page check, lines 72–75)

**Interfaces:**
- Consumes: `id="app-grid"` and `/* status-probe */` markers from Task 3.

- [ ] **Step 1: Extend the landing check**

Replace the landing-page block at the end of `scripts/smoke.sh`:

```bash
# Portal reachable with the session, and actually the portal: the rendered
# page must contain the app grid and the status-probe script.
landing_body=$(run_curl "landing page request" -b "$JAR" "$BASE/")
grep -q 'id="app-grid"' <<<"$landing_body" \
  || fail "landing page is missing the app grid"
grep -q 'status-probe' <<<"$landing_body" \
  || fail "landing page is missing the status probe script"
echo "ok: portal page (app grid + status probe)"
```

- [ ] **Step 2: Run the full smoke against dev**

```bash
make up-dev   # if not already running
./scripts/smoke.sh
```

Expected: `SMOKE PASS` with the new `ok: portal page (app grid + status probe)` line, and all four header-contract checks still green.

- [ ] **Step 3: Commit**

```bash
git add scripts/smoke.sh
git commit -m "test: smoke asserts portal grid and status probe"
```

---

### Task 5: Manual verification (password change + job survival)

**Files:**
- Modify: `README.md` (append observed behaviour to the "User accounts" section and a new "Session behaviour" note)

**Interfaces:**
- Consumes: running `make up-dev` stack from Tasks 3–4.

This task is manual by nature; the deliverable is the verified behaviour plus its documentation. **Ship-gate from the spec:** if password change demands an elevated-session one-time code, the feature does not ship half-working — stop and evaluate `identity_validation` options first.

- [ ] **Step 1: Verify the password-change flow**

In a browser against the dev stack: log in as the dev user (`jane.doe` / dev password from `authelia/users.yml`), open `https://127.0.0.1/auth/settings`, change the password, log out, log back in with the new password. Record: whether a one-time code was demanded (check `docker compose exec authelia cat /data/notification.txt` if so), and whether the change persisted in `users.yml`.
Expected: change succeeds with only the current password; no OTC involved.

- [ ] **Step 2: Verify job survival across session expiry**

Temporarily set `expiration: 2m` and `inactivity: 1m` in `authelia/configuration.yml`, restart authelia (`docker compose -f docker/compose.yaml -f docker/compose.override.yaml restart authelia` with the repo's env file), log in, start a long request against `/whoami/` streaming... whoami has no long jobs — instead verify at the contract level: log in, wait past expiry, and confirm (a) an in-flight `curl -N` streaming request opened before expiry is not severed at expiry, and (b) the next new request 302s to `/auth`. Then **revert the session values to the Task 1 settings** and restart.
Expected: established connection survives; next request redirects. Record both observations.

- [ ] **Step 3: Document observations**

Append to README under "User accounts" (adjust to what was actually observed — do not document expected behaviour as observed if it differed):

```markdown
### Session behaviour

Sessions last 12 h (4 h inactivity timeout; "remember me" 2 months).
On expiry, in-flight requests/streams are not severed — forward-auth gates
each new request — so server-side jobs keep running; the next UI request
redirects to the login portal, and the page resumes after re-login.
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: verified password-change flow and session-expiry behaviour"
```

---

### Task 6: Release prep

**Files:**
- Modify: `VERSION` (0.2.0 → 0.3.0)
- Modify: `README.md` (routing/portal description touch-up if the routing table or landing description mentions the old link-list page)

**Interfaces:**
- Consumes: everything above, green.

- [ ] **Step 1: Bump VERSION**

`VERSION` becomes exactly:

```
0.3.0
```

- [ ] **Step 2: Sync README portal description**

Search `README.md` for the landing-page description (`grep -n -i "landing" README.md`) and update any wording describing a plain link list to describe the portal (tiles, status indicators, account settings link). Keep it to 1–3 lines; the runbook character of the README stays.

- [ ] **Step 3: Final validation sweep**

```bash
docker compose --env-file .env -f docker/compose.yaml config --quiet
make up-dev && ./scripts/smoke.sh
make down
```

Expected: compose silent; `SMOKE PASS`.

- [ ] **Step 4: Commit and push branch**

```bash
git add VERSION README.md
git commit -m "release: v0.3.0 — session tuning, password self-service, portal"
git push -u origin feature/rollout-readiness
```

PR to `main`; the `release-tag` workflow mints `v0.3.0` on merge.

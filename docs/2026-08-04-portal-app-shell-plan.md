# edge-plane portal — inset-canvas frame + user menu (implementation plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Final step of the federation "app-like look and feel" rollout
(spec: `infra-ui/docs/2026-08-04-app-shell-federation-design.md` in the
infra-ui repo): the portal adopts the inset-canvas frame (page background =
chrome tint, content on a bordered canvas, tiles unchanged) and replaces
the outlined sign-out link with the apps' `name ▾` user-menu pattern.

**Architecture:** Single-page change in `landing/index.html` (Go-templated
static HTML, vanilla JS, vendored tokens) plus a tokens re-vendor that
brings in `--color-chrome`. `authcode/index.html` is untouched (single
centered column, no chrome frame there).

**Tech Stack:** Caddy `templates` + static HTML/CSS/JS; vendored
`landing/tokens.css` from `@infra/ui`.

## Global Constraints

- Airgap-first: no runtime fetches; tokens are re-vendored manually with
  the header contract (`scripts/check-tokens-vendor.sh`).
- Every `font-size` and `border-radius` in the portal must resolve to a
  vendored `--text-*`/`--radius-*` token (or CSS-wide keyword /
  `border-radius: 50%`) — `scripts/check-no-literal-dimensions.sh` gates.
- Bilingual EN/DE via the existing `{{if $de}}` pattern for every new
  user-visible string.
- The trusted-header contract and Caddyfile are untouched.
- Progressive degradation: with JS off the page must still expose a
  working sign-out (plain link) — mirror the `<details>` fallback ethos.
- Confidentiality: synthetic data only; no local machine paths committed.
- Working branch: `feature/app-shell` (controller creates it with this
  plan committed). Do not push.

---

### Task 1: Re-vendor tokens (v0.9.1) + inset-canvas frame

**Files:**
- Modify: `landing/tokens.css` (re-vendor from the local
  `../infra-ui` checkout at tag `v0.9.1` —
  copy the BODY of its committed `dist/tokens.css` verbatim and update the
  header's canonical-source line to `tag v0.9.1 (commit <full sha of the tag>)`
  keeping the header's shape per the existing file)
- Modify: `landing/index.html` (style block + one structural wrapper)

**Interfaces:**
- Produces: `--color-chrome` available; page structure
  `body(bg: chrome) > header.topbar > div.canvas(bg, border-top) > main`.

- [ ] **Step 1: Re-vendor `landing/tokens.css`.** Copy the body of
  `/…/infra-ui`'s committed `dist/tokens.css` at the pinned commit
  verbatim below the header comment; update ONLY the canonical-source
  header line as above. (Get the file with
  `git -C ../infra-ui show v0.9.1:dist/tokens.css` (and `git -C ../infra-ui rev-list -n1 v0.9.1` for the sha).)
  Run `./scripts/check-tokens-vendor.sh` — must pass.

- [ ] **Step 2: Frame the page.** In `landing/index.html`:
  - In the `:root` alias block add `--chrome: var(--color-chrome);` (with
    a one-line comment noting it ships since infra-ui v0.9.1).
  - `body { … background: var(--bg); … }` → `background: var(--chrome);`.
  - `header.topbar`: remove the `border-bottom` (the chrome is one frame,
    like AppShell's header).
  - Wrap `<main>…</main>` in `<div class="canvas">…</div>` and add:

```css
  /* The work canvas: content sits on the base background inset into the
     chrome tint, mirroring the apps' AppShell (no sidebar → border-top
     only, full width, no corner radius — the translator/Nextext shape). */
  .canvas { width: 100%; flex: 1; background: var(--bg);
            border-top: 1px solid var(--border);
            display: flex; flex-direction: column; align-items: center; }
```

  (main keeps its own width/padding; body keeps `align-items: center` —
  the canvas also centers its child so nothing shifts.)

- [ ] **Step 3: Validate**

```bash
./scripts/check-no-literal-dimensions.sh && ./scripts/check-tokens-vendor.sh
```

Expected: both pass (no new font-size/radius literals were introduced).

- [ ] **Step 4: Commit**

```bash
git add landing/tokens.css landing/index.html
git commit -m "feat(portal): inset-canvas frame on the chrome tint; vendor tokens v0.9.1"
```

---

### Task 2: `name ▾` user menu replaces the outlined sign-out link

**Files:**
- Modify: `landing/index.html` (topbar markup, style block, one JS IIFE)

**Interfaces:**
- Consumes: the existing `$name` template variable and dialog visual
  language. Produces: a `#user-menu` button + `#user-menu-panel` dropdown
  whose only item is the sign-out link (`/auth/logout`).

- [ ] **Step 1: Markup.** Replace the topbar's
  `<span class="whoami">…</span>` and `<a class="signout">…</a>` with
  (keeping the spacer and theme toggle in place; the greeting text is
  absorbed by the menu button, matching the apps):

```html
  <span class="spacer"></span>
  <button id="theme-toggle" …unchanged…></button>
  <div class="user-menu-root">
    <button id="user-menu" type="button" aria-haspopup="menu" aria-expanded="false"
            aria-label="{{if $de}}Konto: {{$name | html}}{{else}}Account: {{$name | html}}{{end}}">
      <strong>{{$name | html}}</strong><span class="caret" aria-hidden="true">&#9662;</span>
    </button>
    <div id="user-menu-panel" role="menu" hidden>
      <a role="menuitem" href="/auth/logout">{{if $de}}Abmelden{{else}}Sign out{{end}}</a>
    </div>
    <noscript><a class="signout" href="/auth/logout">{{if $de}}Abmelden{{else}}Sign out{{end}}</a></noscript>
  </div>
```

  (Order: spacer → toggle → menu, exactly AppShell's header. The
  `noscript` link keeps the no-JS sign-out path; the `.signout` CSS class
  stays for it.)

- [ ] **Step 2: Styles** (all sizes/radii via tokens; panel reuses the
  dialog language):

```css
  /* User menu: the apps' `name ▾` pattern (UserMenu). Button geometry
     matches the sign-out control it replaces (2rem, radius-lg); the
     panel reuses the tile-dialog surface language. */
  .user-menu-root { position: relative; }
  #user-menu { display: inline-flex; align-items: center; gap: .375rem;
               height: 2rem; padding: 0 .75rem; cursor: pointer;
               background: none; font: inherit; color: var(--muted);
               border: 1px solid var(--border); border-radius: var(--radius-lg); }
  #user-menu strong { color: var(--text); }
  #user-menu:hover, #user-menu[aria-expanded="true"] { border-color: var(--accent); color: var(--text); }
  #user-menu .caret { font-size: var(--text-xs); }
  #user-menu-panel { position: absolute; right: 0; top: calc(100% + .25rem);
                     min-width: 10rem; z-index: 30; padding: .25rem;
                     background: var(--surface); border: 1px solid var(--border);
                     border-radius: var(--radius-lg); }
  #user-menu-panel a { display: block; padding: .375rem .75rem;
                       color: var(--text); text-decoration: none;
                       font-size: var(--text-sm); border-radius: var(--radius-md); }
  #user-menu-panel a:hover { background: var(--bg); }
```

- [ ] **Step 3: JS** (new IIFE beside the theme-toggle one):

```js
/* user-menu: the apps' name ▾ dropdown. Escape and outside-click close;
   aria-expanded tracks state. The noscript sign-out link covers JS-off. */
(function () {
  var btn = document.getElementById('user-menu');
  var panel = document.getElementById('user-menu-panel');
  if (!btn || !panel) return;
  function setOpen(open) {
    panel.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
  }
  btn.addEventListener('click', function () { setOpen(panel.hidden); });
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') setOpen(false);
  });
  document.addEventListener('mousedown', function (ev) {
    if (!btn.parentElement.contains(ev.target)) setOpen(false);
  });
})();
```

- [ ] **Step 4: Validate + commit**

```bash
./scripts/check-no-literal-dimensions.sh
git add landing/index.html
git commit -m "feat(portal): name ▾ user menu replaces the outlined sign-out link"
```

---

### Task 3: Release bump + CI-equivalent validation

**Files:**
- Modify: `VERSION` (`0.4.3` → `0.5.0`)

- [ ] **Step 1: Bump `VERSION`** to `0.5.0` (feature-level UI change; the
  release-tag workflow mints the tag on merge).

- [ ] **Step 2: Local CI equivalents**

```bash
docker compose --env-file .env -f docker/compose.yaml config --quiet
./scripts/check-tokens-vendor.sh
./scripts/check-no-literal-dimensions.sh
```

(Skip `caddy validate` / `smoke.sh` locally unless docker + a dev stack
are already up; CI runs the validation matrix. If `.env` is missing, run
the compose check with `EDGE_HOST=example.internal` env instead.)

- [ ] **Step 3: Commit**

```bash
git add VERSION
git commit -m "chore: v0.5.0"
```

- [ ] **Step 4: STOP — do not push.** The controller holds the branch
  until the user green-lights the portal PR.

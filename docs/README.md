# edge-plane documentation

This directory holds the operator runbooks and reference material for
**edge-plane**, the federation's edge gateway. It complements the top-level
[`README.md`](../README.md) — which covers what the gateway is, what it
routes, and how to get it running — with the topic-by-topic detail that
would otherwise bury it.

## Table of contents

| Document | What it covers |
|---|---|
| [configuration.md](configuration.md) | Every environment variable with its default, the UI-language switch, corporate-proxy bypass |
| [user-accounts.md](user-accounts.md) | Provisioning users, the first-start storage key and how to recover from rotating it, self-service password change, admin-mediated resets, session lifetimes |
| [tls-runbook.md](tls-runbook.md) | The two certificate sources — Caddy's internal CA and an org-issued PEM pair — client trust distribution, the `EDGE_HOST` caveat, recovery after `make nuke` |
| [identity-contract.md](identity-contract.md) | The strip → authenticate → inject header flow, `X-Auth-User`/`Email`/`Groups`/`Name`, the `Authorization` pass-through rule, and the admins-group `/grafana` gate |
| [images.md](images.md) | Pinned image digests (the source of truth CI and compose must match) and what the airgap bundle contains |
| [portal-tokens.md](portal-tokens.md) | The vendored `@infra/ui` design tokens behind the static portal pages: re-vendoring procedure and the CI checks that guard it |
| [decisions/](decisions/) | Architecture decision records — the choices that would be expensive to reverse, and why |

Design history lives alongside these as dated `YYYY-MM-DD-*.md` files;
they record what was decided at a point in time and are not kept current.

## Who this is for

- **Operators** standing up or running the gateway — start with
  [configuration.md](configuration.md), then
  [tls-runbook.md](tls-runbook.md) and
  [user-accounts.md](user-accounts.md).
- **App developers** whose service sits behind the gateway and consumes
  the injected identity — go straight to
  [identity-contract.md](identity-contract.md).
- **Anyone adding a member to `edge-net`** — read
  [identity-contract.md](identity-contract.md) first: membership is an
  access-control decision, because members accept the injected headers
  unverified.
- **Anyone touching the portal pages** — see
  [portal-tokens.md](portal-tokens.md) before editing
  `landing/` or `authcode/`; both files are guarded by CI checks.

## Conventions used in these docs

- **Paths are relative to the repo root** (for example `caddy/Caddyfile`,
  `docker/compose.yaml`) so they resolve the same from a shell and from a
  file browser.
- **Environment variables** are named exactly as they appear in
  `.env.example`; defaults quoted here are the ones baked into
  `docker/compose.yaml`.
- **Anything marked "verified"** was observed in a real bring-up, not
  inferred from configuration.
- Documentation is plain Markdown (GitHub Flavored). There is no docs
  build step.

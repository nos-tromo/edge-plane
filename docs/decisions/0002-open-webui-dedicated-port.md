# 0002 — Open WebUI on a dedicated port, not a sub-path

Status: accepted (2026-07-24)
Date: 2026-07-24 (decision); recorded 2026-08-22, moved out of `README.md`

## Context

The gateway's routing model is path-based: one hostname, one `:443` site,
each application served under its canonical sub-path (`/chorus/`,
`/docint/`, `/nextext/`, `/translator/`, `/grafana/`). The prefix is not
stripped — each upstream is configured to serve from its sub-path, so
asset URLs, router base paths and redirects all stay consistent behind the
gateway. `docs/2026-07-23-edge-plane-design.md` assumed Open WebUI would
join on the same terms, at `/webui/`.

It cannot. The upstream image has no base-path support: its SvelteKit
frontend bakes root-absolute asset paths (`/_app/...`) at image build
time, with no runtime env to rewrite them (confirmed against the pinned
image's config and the `v0.9.6` source — no `WEBUI_BASE_URL`/`root_path`
mechanism exists). Served under `/webui/`, the HTML loads and every asset
request then escapes the prefix and 404s at the gateway.

## Decision

Open WebUI gets its own Caddy site on a dedicated port,
`https://<EDGE_HOST>:8443/`, rather than a path on the main site. It runs
the same `strip_identity` + `authed` chain as every other upstream, so the
identity contract is unchanged. `:8443` is published alongside `:443`/`:80`
as the only other host-port exception in the production federation.
`/webui` and `/webui/*` on the main site remain matched, and redirect to
the `:8443` origin.

## Alternatives considered

- **Rewrite the assets at the gateway.** Caddy could strip `/webui` and
  rewrite root-absolute asset paths on the way back. That means
  content-rewriting HTML and JS in the proxy — fragile against any upstream
  change, and it does not fix paths constructed at runtime by the client.
- **Build a patched image.** Abandons the pulled, digest-pinned upstream
  image and the airgap bundle shape that goes with it, to carry a fork of a
  fast-moving frontend.
- **Give it a separate hostname.** The deployment has no DNS control — the
  whole path-based design exists because there is one hostname or IP. A
  second name would have to be provisioned on every client's `/etc/hosts`.

## Consequences

- A second port must be reachable from client machines. Anything between a
  browser and the gateway (host firewall, LAN ACLs) has to allow `:8443`
  as well as `:443`.
- The `/webui` handle **cannot** carry `forward_auth`: Caddy orders `redir`
  before `forward_auth`, so a check there would never run. Authentication
  is enforced at the destination instead — the `:8443` site gates every
  request.
- The `:8443` site caps long-lived streams at `stream_timeout 30m`.
  `forward_auth` gates only the WebSocket upgrade, so without the cap an
  open socket (socket.io) would outlive the Authelia session indefinitely.
  Re-upgrades pass back through `forward_auth`.
- Open WebUI's SSO is keyed on email (`WEBUI_AUTH_TRUSTED_EMAIL_HEADER=X-Auth-Email`)
  rather than `X-Auth-User`, and it issues its own JWTs afterwards — which
  is why `Authorization` passes through the gateway untouched. See
  [../identity-contract.md](../identity-contract.md).
- `docs/2026-07-23-edge-plane-design.md`'s routing map is superseded on
  this point; `README.md`'s routing table is authoritative.

## Revisiting

If Open WebUI gains a runtime base-path mechanism, this collapses back into
a `/webui/` route on the main site: one `handle` block with `import authed`
plus a `reverse_proxy open-webui:8080`, the `:8443` site and its published
port both deleted. The identity contract does not change either way.

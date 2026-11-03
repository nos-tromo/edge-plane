# 0001 — ACME issuance against an internal CA

Status: deferred (2026-08-01) — see *Why deferred*
Date: 2026-08-01

## Context

edge-plane terminates TLS for the whole federation. Two certificate sources
are supported today, selected by the `EDGE_TLS` variable that both site blocks
interpolate as `tls {$EDGE_TLS:internal}`:

- **unset** → `tls internal`: Caddy's own CA mints the leaf. Self-renewing,
  zero external dependency, but the root has to be exported
  (`make ca-export`) and installed into every client's trust store.
- **a PEM path pair** → an org-issued certificate bind-mounted read-only at
  `/etc/caddy/certs`. No client-side trust work if the issuing CA is already
  trusted, but **renewal is manual**: drop in a new pair, `make restart`.

ACME was excluded deliberately when the gateway was designed. The Caddyfile
opens with `Airgap: internal CA only — no ACME, no OCSP, no egress`, sets
`skip_install_trust` in the global block, and the same call is recorded in
`CLAUDE.md`, `README.md`, and `docs/2026-07-23-edge-plane-design.md`. It
follows from the federation-wide airgap invariant: *do not add anything that
fetches data at runtime*.

That exclusion was made for the airgapped deployment shape. A second shape is
now in play: a single host on an organization's LAN, serving wired client
computers, where the org runs its own internal CA. In that shape the manual
renewal path is a standing operational obligation with a hard failure mode —
if nobody replaces the PEM pair before expiry, every user loses access to
every application at once, and the person who set it up may no longer be the
person on call. An internal ACME endpoint, if the org operates one, removes
that obligation entirely.

This record exists because taking that option is not a configuration tweak.
It reopens a documented architectural decision, and the reasoning should be
written down rather than discovered later in a Caddyfile diff.

## Why deferred

Not rejected on the merits — deferred because the feature's value depends
entirely on infrastructure edge-plane does not control and cannot verify.

Enabling ACME would mean carrying a code path whose viability rests on four
facts about the organization's PKI, none of them established:

1. That an internal ACME endpoint exists at all.
2. That it supports a challenge type Caddy can satisfy out of the box.
   HTTP-01 and TLS-ALPN-01 are fine — the gateway already publishes `:80`
   and `:443`. **DNS-01 is not**: it needs a DNS-provider module compiled
   into Caddy, which means abandoning the pulled, digest-pinned upstream
   image for a custom build and reworking the airgap bundle. That single
   fact would change this from a small change to a substantial one.
3. Whether it requires EAB (External Account Binding) credentials — common
   with enterprise ACME, and another secret to provision and rotate.
4. Whether its own TLS certificate is already trusted, which decides whether
   `acme_ca_root` is needed (see *Implementation notes* — that option is not
   inert when unused).

Shipping a third certificate source that may turn out to be unusable adds a
maintenance surface, a documentation branch, and a `make smoke` case for no
delivered benefit. The org-issued PEM pair works today, needs nothing from
anyone else at runtime, and reverses into ACME cheaply if the picture changes.

Revisit if: the org confirms an ACME endpoint with HTTP-01 or TLS-ALPN-01
support, **and** manual renewal has actually become a burden (a missed
expiry, or the deployment growing past one host).

## Decision

*(Not taken — recorded for a future revisit.)* Support ACME against an
internal CA as a **third**, opt-in certificate source, alongside — never
replacing — the existing two.

- Add `acme_ca <internal ACME directory URL>` to the Caddyfile global options
  block, and `acme_ca_root` where the endpoint's own certificate is not
  already trusted.
- Select the issuer through the existing `EDGE_TLS` variable — no site-block
  change (see *Implementation notes*).
- `skip_install_trust` stays set — the container's trust store is not the
  mechanism; the root is supplied explicitly.
- Accept a standing outbound dependency from the gateway host to the internal
  CA, scoped to the LAN.
- Keep `internal` the default. An operator who sets nothing gets today's
  behavior, and the airgapped shape is unaffected.

The airgap invariant is not repealed. It is narrowed: *airgapped deployments
fetch nothing at runtime; a LAN deployment may depend on LAN-internal
infrastructure it already depends on for identity and DNS.*

## Alternatives considered

- **Keep the internal CA (status quo default).** No external dependency at
  all and renewal is automatic — genuinely the best option on an isolated
  host. Rejected for the LAN shape only because it pushes the work onto every
  client: the root must be installed on each machine, and re-installed for
  all of them if `edge-ca` is ever destroyed (`make nuke` mints a new root).
- **Org-issued PEM pair, renewed by hand.** The fallback if the preconditions
  fail, and entirely workable. Costs one calendar entry per certificate
  lifetime and carries the expiry failure mode described above. Its virtue is
  that it adds no runtime dependency whatsoever — the certificate is a file.
- **Public ACME (Let's Encrypt or similar).** Not possible and not wanted:
  there is no public DNS record for `<EDGE_HOST>` and no inbound path from
  the internet, so neither HTTP-01 nor TLS-ALPN-01 can validate. DNS-01 would
  require handing an external CA authority over an internal name.
- **Request a very long-lived certificate** (5–10 years) to push the problem
  out. Defers rather than solves, and long validity periods are exactly what
  internal PKI policies tend to prohibit.

## Consequences

- Positive: no manual renewal, no calendar obligation, no expiry outage. No
  client-side trust distribution either, since the org CA is already trusted
  on managed machines. The operational story for a LAN deployment becomes
  strictly simpler than both existing options.
- Negative: the gateway acquires a runtime dependency on infrastructure
  outside the compose project. If the CA is unreachable across a renewal
  window, the certificate expires and the entire federation becomes
  unreachable — the same failure as the manual path, but triggered by someone
  else's outage rather than by forgetting.
- Negative: the certificate-source matrix goes from two cases to three, and
  `.env.example`, the README's TLS section, and the global-options snippet
  have to stay consistent. `make smoke` should cover the ACME shape or it
  will rot.
- Negative: the repo can no longer state "no ACME, no egress" unconditionally.
  The Caddyfile header comment, `CLAUDE.md`, `README.md`, and the design doc
  all need the narrowed wording, or they become false for the LAN shape.
- Neutral: no change for existing deployments. Both current modes keep working
  untouched, and the airgapped shape is unaffected by construction.
- Reversal trigger: the org's ACME endpoint proves unreliable, its issuance
  policy changes in a way that breaks unattended renewal, or the host moves
  into an airgapped environment. Reversal is cheap and does not need a
  migration — obtain a PEM pair, set `EDGE_TLS` to the file paths, restart.
  That property is the reason for keeping all three sources rather than
  switching.

## Implementation notes (verified 2026-08-01)

Established empirically with `caddy validate` against the pinned image
(`caddy:2.11.4`, digest in `docs/images.md`), so a revisit starts from facts
rather than a sketch:

- **The site blocks need no change.** `tls {$EDGE_TLS:internal}` is textual
  substitution, and Caddy's one-line `tls <email>` form *is* the ACME form.
  All three values validate: `internal`; a `<cert> <key>` path pair; and an
  email address, which selects ACME. The third mode rides the existing `.env`
  switch.
- **`acme_ca` takes a placeholder default safely.** With `EDGE_ACME_CA` unset,
  `acme_ca {$EDGE_ACME_CA:https://acme.invalid/directory}` still validates and
  is never contacted unless `EDGE_TLS` is an email. Existing deployments are
  unaffected.
- **`acme_ca_root` is not inert when unused.** It is a real global option in
  2.11.4, but a missing file at its path fails startup *even with
  `EDGE_TLS=internal`* — the ACME issuer module is provisioned regardless. So
  it cannot carry a placeholder default and must be conditional.
- **`import` works inside the global options block**, and an empty glob
  directory validates clean. So the conditional above is solved by the idiom
  already in this repo: a `caddy/global.d/` (empty) vs `caddy/global.d.acme/`
  directory swap, selected by the mounted source dir — the same shape as the
  existing `conf.d` / `conf.d.dev` dev swap, but chosen via `.env` rather than
  a compose override, since ACME would be a production mode.

Estimated change: roughly 60–80 lines across 8 files, **under 10 of them
config** — one `import` line in the Caddyfile, a ~4-line snippet file, one
compose mount, and the rest documentation. Half a day, most of it a live
issuance test that cannot be run without a real endpoint.

Files that would move together, per the convention that documentation rides
with the change that stales it: Caddyfile (+ its header comment),
`docker/compose.yaml`, `.env.example`, `README.md`, `CLAUDE.md`,
`docs/2026-07-23-edge-plane-design.md`, `scripts/smoke.sh`, and this record.

The DNS-01 case in *Why deferred* is the exception to that estimate — it
would require a custom Caddy build and is a different piece of work entirely.

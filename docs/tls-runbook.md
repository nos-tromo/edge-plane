# TLS / CA runbook

Caddy terminates TLS using its own internal CA by default (`EDGE_TLS`
unset → `tls internal` in the Caddyfile) — there is no ACME, no external
CA, and no egress, consistent with the airgap-first rule. There are two
supported cert sources.

## Option A (default): internal CA

To make LAN browsers trust it:

```bash
make ca-export                # writes edge-ca-root.crt (Caddy's internal CA root)
```

Distribute `edge-ca-root.crt` to every browser/OS that will reach the
gateway and install it as a trusted root CA (the exact steps are
OS/browser-specific: e.g. macOS Keychain Access "always trust", Windows
Certificate Manager "Trusted Root Certification Authorities", Firefox's
own cert store on Linux). Until a browser trusts the root, it shows a
certificate-warning interstitial — that is the accepted fallback for a
LAN deployment with no public CA, not a bug; clicking through is safe
because the certificate is generated locally on the gateway host, not
downloaded from anywhere.

For Linux clients, `scripts/client-setup.sh` does the whole client side in
one idempotent run — the `/etc/hosts` entry, the system trust store, and
Firefox's enterprise policy — from the exported root:

```bash
sudo ./client-setup.sh <edge-host> <gateway-ip> <path/to/edge-ca-root.crt>
```

See the script's own header comment for what each step does and when
steps 2-3 become unnecessary.

## Option B: org-issued certificate

If your organization runs an internal CA that managed clients already
trust (the usual case when an org-provided domain points at the
federation host), skip the root-distribution step entirely: have the org
issue a certificate for the `EDGE_HOST` name, then

1. place the PEM pair in `certs/` (gitignored; never commit certs or
   keys):
   `certs/cert.pem` (leaf, plus any intermediate chain) and
   `certs/key.pem`
2. set in `.env`:
   `EDGE_TLS=/etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem`
3. `make restart`

The `certs/` directory is bind-mounted read-only into the container at
`/etc/caddy/certs`. Certificate rotation is the same three steps with a
new PEM pair. Reverting to the internal CA = unset `EDGE_TLS` and
restart. The `edge-ca` volume and `make ca-export` remain functional
either way (the internal CA is simply unused while `EDGE_TLS` points at
org PEMs). Renewal is manual — the airgap rule means nothing renews
itself, so track the org cert's expiry in whatever calendar the host's
backups live in.

## EDGE_HOST caveat

`EDGE_HOST` must be a dotted hostname or an IP
address — Authelia's cookie-domain validation (RFC 6265) rejects
dot-less names like `localhost`. An IP address works fine for dev/CI
(both use `127.0.0.1`); the recommended production shape is a real
dotted hostname distributed via `/etc/hosts` entries (or LAN DNS, if
available) on every client machine, since a hostname survives an IP
change and reads better in a browser address bar. The Caddyfile also
sets `default_sni {$EDGE_HOST}` — this is required because RFC 6066
forbids the SNI extension for literal IP addresses, so when `EDGE_HOST`
is an IP no conformant TLS client sends SNI at all; without a default
site, every such handshake fails with a TLS `internal_error` alert
before Caddy ever routes the request.

## Recovering after `make nuke`

`make nuke` destroys the `edge-ca` volume, which holds Caddy's internal
CA including its private key. Recovery is not a restart: destroying
`edge-ca` mints a **new** root CA on the next `make up`, so every browser
that trusted the old root must re-run Option A above — `make ca-export`,
redistribute, re-trust — before it will reach the gateway without an
interstitial. The same command destroys `edge-state`, so every user also
loses their session and must re-authenticate.

None of this applies under Option B: while `EDGE_TLS` points at org PEMs
the internal CA is unused, so a new root is irrelevant to clients.

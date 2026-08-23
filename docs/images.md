# Pinned images

| Role | Image |
|---|---|
| gateway | docker.io/library/caddy:2.11.4@sha256:844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9 |
| auth | docker.io/authelia/authelia:4.39.20@sha256:1b363e9279e742397966333f364e0876ae02bf5c876de73e83af6d48c57ff51b |
| dev header-echo (never bundled) | docker.io/traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab |

When bumping an image, update the digest pin in `docker/compose.yaml`,
this file, and `.github/workflows/ci.yml` together.

## Airgap bundling

Both pulled images (`caddy`, `authelia`) are saved as a versioned airgap
tarball via the shared `scripts/bundle-lib.sh` (vendored, CI
drift-checked against `nos-tromo/.github`), matching the
data-plane/obs-plane pattern: bespoke Makefile, no `bundle-dev` target,
version override via env instead. `docker.io/traefik/whoami` (the dev
header-echo upstream) is never bundled — it has no place in a production
airgap image set.

# CLAUDE.md: wolfi-platform-images

A **public** repository that builds minimal container images from Wolfi packages
(apko, melange for source builds), gates them on CVEs, SBOMs them and signs them
keylessly, then publishes to GHCR with a signed `release.json`. Read `README.md`
first.

## Rules
- **Public repository.** Never add internal project names, codenames, product or
  customer names, private repository references, internal ticket or decision IDs,
  credentials or deployment details. Comments explain the image on its own terms.
- **Pin everything.** Wolfi packages in recipes (`name=version`) and lock files;
  source builds by tag and full `expected-commit`; tools in `Taskfile.yml`; actions
  by commit SHA. New versions must be at least two weeks old.
- **Source builds** set `GOTOOLCHAIN=local` and name packages `<name>-src`.
- **The CVE gate is not bypassed.** Accept a finding only in `cve-exceptions.yaml`,
  per image, with a written reachability reason, an owner and an expiry.
- **Signing happens only in `publish.yml` on `main`.** Pull requests build and gate
  but never get an OIDC token, write access or secrets; never use `pull_request_target`.
  The signing identity in `images.yaml` must match the workflow path exactly.
- **Tests:** positive and negative cases for every check (lint, gate, signing,
  skip-existing). `task lint`, `task test` and `task images:test` run locally and in CI.
- Diagrams in Markdown use Mermaid; `task lint:mermaid` proves they parse.
- Suppress an ASH finding only in `.ash/.ash.yaml`, with a written reason.

## Commands
- `task tools`, `task lint`, `task test`
- `task images:lint` / `images:plan` / `images:lock` / `images:test` (`FACTORY_DOCKER=1` for source builds)
- `task images:build ONLY=… TARGET=… KEY=…` (without `KEY`: keyless, CI only)
- `task ash` (`ASH_MODE=local` for a quick pass)

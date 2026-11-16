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
- **Nothing is built or published without tests.** Every image is staged, CVE-gated
  and functionally tested (`tests/functional`, marked `@pytest.mark.image(...)`, run
  hardened against the staged digest) before `promote` copies exactly that digest to
  the registry. A new image needs real functional tests (its actual job, plus a
  negative case), not a version check. Never rebuild between test and publish.
- **Tests:** positive and negative cases for every check (lint, gate, signing, reuse,
  promote). `task lint`, `task test` and `task images:test` run locally and in CI.
- Diagrams in Markdown use Mermaid; `task lint:mermaid` proves they parse.
- Suppress an ASH finding only in `.ash/.ash.yaml`, with a written reason.

## Commands
- `task tools`, `task lint`, `task test`
- `task images:lint` / `images:plan` / `images:lock`
- `task images:test` = `images:stage` (build, gate, stage) + `images:functest` + `images:verify`
- `task images:promote TARGET=… KEY=…` (without `KEY`: keyless, CI only); refuses untested images
- `task status` measures the published images and writes the status site (`.build/site`)
- `task update` applies newer Wolfi packages and upstream releases past the 14-day cooldown (the daily
  `update.yml` opens a pull request and dispatches CI on it); smoke expectations use `{version}`
- `task ash` (`ASH_MODE=local` for a quick pass)

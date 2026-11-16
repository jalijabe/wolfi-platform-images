# Security policy

Report a vulnerability in these images, their recipes or the build and publish
workflows through GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. Please do not open a public issue.

Known CVEs in published images are handled by the CVE gate: findings at or above
`high` block publishing unless [`cve-exceptions.yaml`](cve-exceptions.yaml)
accepts them with a written reason and an expiry. If you think an accepted
finding is reachable, report it as above.

Only images signed by this identity are ours:

- identity: `https://github.com/jalijabe/wolfi-platform-images/.github/workflows/publish.yml@refs/heads/main`
- issuer: `https://token.actions.githubusercontent.com`

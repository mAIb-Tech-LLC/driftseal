# Local CLI and privacy

Install the public source package with Python 3.12+ or use the npm wrapper when published. The npm wrapper requires Python and has no install scripts.

```sh
driftseal scan                         # current local directory
driftseal scan ./manifest.json --json
driftseal scan @scope/package --json
driftseal scan pypi:mcp --sarif
driftseal scan https://github.com/owner/repo
driftseal baseline ./tools --output approved.json
driftseal diff approved.json current.json --fail-on critical
driftseal login
driftseal watch @scope/package
driftseal status --json
driftseal logout
driftseal version
```

`--output` writes JSON/SARIF when the corresponding format option is supplied. Exit codes: 0 below threshold, 1 threshold reached, 2 failure. Baseline creation refuses to overwrite an existing approval.

**Local paths and stdin never upload source or scan telemetry.** They exclude credential files, symlinks, `.git`, virtual environments and `node_modules`. Reports include relative paths, descriptions/schemas, fingerprints and findings. Redaction is best effort; review reports before sharing them. No redactor can identify all possible secret formats.

Public package scans contact registry/artifact services and OSV. GitHub scans contact GitHub's API/archive host. MCP scans send only the read-only `tools/list` metadata request. Cloud `watch` sends a public component coordinate. v0.1 has no private evidence upload endpoint.

CLI login uses a console-generated token entered through a hidden prompt, stored with permissions 0600 at `~/.config/driftseal/credentials.json`. Tokens expire after 14 days. Logout revokes the current token. Configure `DRIFTSEAL_CONFIG_DIR` for an alternative location.


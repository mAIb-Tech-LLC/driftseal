# DriftSeal

**Know when an MCP server, agent skill or tool changes after you trusted it.**

A point-in-time scan checks what is there now. An approved baseline makes later changes reviewable. Continuous WATCH monitoring checks public components between commits.

## Add the GitHub Action in one minute

Save this as `.github/workflows/driftseal.yml`. Set `path` to your agent tool/skill directory or JSON manifest.

```yaml
name: DriftSeal
on: [pull_request, push]
permissions:
  contents: read
jobs:
  driftseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mAIb-Tech-LLC/driftseal@v1
        with:
          path: ./agent-tools
          fail-on: critical
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: driftseal-evidence
          path: ${{ runner.temp }}/driftseal-results/
```

No cloud signup or token. The Action sets up Python 3.12, reads the target without installing or executing it, and produces a job summary, evidence JSON and SARIF. Critical findings fail the job; artifacts remain available. Start without a baseline for static findings. Prefer a reviewed commit pin for stronger provenance.

## Approve a baseline, then review the diff

Requires Python **3.12+**, Linux or macOS:

```sh
python3 -m pip install 'git+https://github.com/mAIb-Tech-LLC/driftseal@v1'
driftseal scan ./agent-tools
driftseal baseline ./agent-tools --output .driftseal-baseline.json
```

Review and commit the baseline. The Action automatically uses `.driftseal-baseline.json` when present. Changes to tools, descriptions, schemas, permissions, dependencies and artifacts appear with old/new evidence and severity. Reapprove deliberately; never regenerate the baseline automatically on every run. Keep the same target directory name locally and in CI.

Exit codes: **0** below threshold, **1** severity threshold reached, **2** operation failed. `--json`, `--sarif` and `--fail-on critical` work locally without signup.

## Want to know when this changes later?

[**WATCH THIS COMPONENT →**](https://drift.maib.io/?source=github-readme#scanner)

WATCH is $9/month for 10 public components checked daily. PRO is $29 for 50 components every six hours. TEAM is $79 for 250 components. Scan, inspect evidence, choose WATCH, sign in and complete checkout. Monitoring starts automatically after payment. The free Action remains useful independently.

Private source stays local. Hosted recurring watches need a public retrievable package, repository or compatible MCP metadata endpoint. The Action never sends your repository name, source or findings to DriftSeal.

## Optional adoption measurement

Automatic telemetry is **off by default**. To contribute anonymous stage counts, set `telemetry: 'true'`. The payload contains a fresh random run ID, a boolean indicating whether a baseline was compared, and an optional random UUID supplied in `installation-id`. Never use a repository name as that ID. No target coordinate, filenames, source, findings or credentials are transmitted. Reporting failure never changes the security result. Without opt-in, DriftSeal cannot count your installation or runs; clicked WATCH links provide referral attribution.

## Public badge without public findings

In the hosted console, choose **Publish status** on a watch, then open **Badge** and copy the Markdown. Publishing is opt-in. The badge links to the last-check timestamp, active ruleset and minimal status. Detailed findings remain private. Unpublish at any time. A badge is monitoring evidence, not a security certification.

## Coverage and installation

Public npm/PyPI artifacts, immutable GitHub commit archives, bounded archives, local paths and explicit JSON tool manifests are supported. Stateless public MCP `tools/list` is supported without tool execution. Dynamic tool generation, authenticated/stateful MCP, YAML structure, binary behavior and transitive dependency resolution are outside coverage.

The npm launcher requires Node 18+ **and Python 3.12+**. It is not yet published to the npm registry; use the source installation above. No zero-dependency installation claim is made.

[Action guide](https://drift.maib.io/docs/github-action?source=github-readme) · [CLI/privacy](docs/CLI.md) · [Security model](docs/SECURITY_MODEL.md) · [Continuous monitoring](https://drift.maib.io/mcp-drift-monitoring?source=github-readme)

Apache-2.0 scanner, CLI and Action. Hosted operations/history are commercial. A mAIb Tech product. A clean result means only that no material issue or drift was detected by the active ruleset and available coverage; it does not guarantee software security.

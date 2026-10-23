# DriftSeal

**Know when an MCP server, agent skill or tool changes after you trusted it.**

A point-in-time scan checks what is there now. An approved baseline makes later changes reviewable.

This repository provides two free, Apache-2.0 tools that run on your own machine or CI runner:

- **GitHub Action** (`mAIb-Tech-LLC/driftseal@v1`): static checks and baseline comparison inside GitHub Actions.
- **CLI** (`driftseal`): the same scanner from a terminal, installed from this repository's source.

DriftSeal also has a separate, commercial hosted service. It is not part of the Action or CLI, is not needed to use them, and is not covered by this README; see [Hosted service](#hosted-service-separate).

## GitHub Action

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

Inputs: `path`, `baseline` (default `.driftseal-baseline.json`), `fail-on` (default `critical`), `telemetry` (default `'false'`) and `installation-id`. Outputs: `result` (JSON path) and `sarif` (SARIF path). See [`action.yml`](action.yml).

## CLI: approve a baseline, then review the diff

Requires Python **3.12+**, Linux or macOS. Install from source:

```sh
python3 -m pip install 'git+https://github.com/mAIb-Tech-LLC/driftseal@v1'
driftseal scan ./agent-tools
driftseal baseline ./agent-tools --output .driftseal-baseline.json
```

Review and commit the baseline. The Action automatically uses `.driftseal-baseline.json` when present. Changes to tools, descriptions, schemas, permissions, dependencies and artifacts appear with old/new evidence and severity. Reapprove deliberately; never regenerate the baseline automatically on every run. Keep the same target directory name locally and in CI.

Exit codes: **0** below threshold, **1** severity threshold reached, **2** operation failed. `--json`, `--sarif` and `--fail-on critical` work locally without signup. More commands and privacy details: [CLI/privacy](docs/CLI.md).

**Release tarball (alternative).** The [v0.1.0 release](https://github.com/mAIb-Tech-LLC/driftseal/releases/tag/v0.1.0) attaches `maib-driftseal-0.1.0.tgz`, a Node launcher for the 0.1.0 scanner. It requires Node 18+ **and Python 3.12+**, and it predates `v1`, so prefer the source installation above. After download, check its SHA-256 (`80765ac61cc8a482bdb64cc44aaf50ea0c93194b3d7cd7b50e907e916a06f872`), extract it and run `node package/bin.cjs version`. It is not published to the npm registry. No zero-dependency installation claim is made.

## Coverage

Public npm/PyPI artifacts, immutable GitHub commit archives, bounded archives, local paths and explicit JSON tool manifests are supported. Stateless public MCP `tools/list` is supported without tool execution. Dynamic tool generation, authenticated/stateful MCP, YAML structure, binary behavior and transitive dependency resolution are outside coverage.

Private source stays local. The Action never sends your repository name, source or findings to DriftSeal, and local CLI scans of paths and stdin never upload source or scan telemetry. [Security model](docs/SECURITY_MODEL.md).

## Optional adoption measurement

Automatic telemetry is **off by default**. To contribute anonymous stage counts, set `telemetry: 'true'`. The payload contains a fresh random run ID, a boolean indicating whether a baseline was compared, and an optional random UUID supplied in `installation-id`. Never use a repository name as that ID. No target coordinate, filenames, source, findings or credentials are transmitted. Reporting failure never changes the security result. Without opt-in, DriftSeal cannot count your installation or runs.

## Hosted service (separate)

DriftSeal's hosted service (recurring monitoring of public components, history, badges and the `driftseal login`/`watch` commands) is a separate commercial product at drift.maib.io with its own terms. Nothing in this README describes its availability, reliability or pricing. Hosted watches need a public retrievable package, repository or compatible MCP metadata endpoint; private source stays local. Publishing a status badge is opt-in, and a badge is monitoring evidence, not a security certification.

In DriftSeal 0.1.0, the Action's job summary and the CLI's text output include a link to the hosted service; following it is optional and the results do not depend on it. From 0.1.1 they link only to this repository's baseline documentation.

Apache-2.0 scanner, CLI and Action. A mAIb Tech product. A clean result means only that no material issue or drift was detected by the active ruleset and available coverage; it does not guarantee software security.

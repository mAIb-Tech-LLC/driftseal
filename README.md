# DriftSeal

The tripwire for your AI agent supply chain. A mAIb Tech product.

## 30-second quick start

Requires Python 3.12+ on Linux or macOS. No cloud signup. No target execution.

```sh
git clone https://github.com/mAIb-Tech-LLC/driftseal.git
cd driftseal
python3 -m pip install .
driftseal scan ./agent-tools --json
driftseal baseline ./agent-tools --output approved.json
driftseal scan ./agent-tools --json --output current.json
driftseal diff approved.json current.json --fail-on critical
```

Public npm/PyPI packages, GitHub repositories, explicit JSON tool manifests and bounded archives are supported. Runtime-generated schemas, authenticated/stateful MCP, YAML structure and binary behavior are outside coverage. The core never installs, imports or executes target code.

`driftseal scan pypi:mcp --sarif` emits SARIF. Exit codes: 0 below severity threshold, 1 threshold reached, 2 operation failed. `--fail-on critical` gates CI.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: mAIb-Tech-LLC/driftseal@v1
  with:
    path: ./agent-tools
    baseline: .driftseal-baseline.json
    fail-on: critical
```

The Action writes a job summary, JSON and SARIF in `${{ runner.temp }}/driftseal-results/`. Upload that directory with `actions/upload-artifact@v4` and `if: always()` to preserve failure evidence. No cloud token is needed. Prefer a verified commit pin for stronger provenance.

## Continuous monitoring

The paid hosted service adds recurring watches, private history, alerts, team policies and dashboards. `driftseal login`, `watch`, `status` and `logout` connect to that service. Use `--url` on login if the deployment uses an alternate URL.

Private path scans upload nothing. Cloud watch sends only a public target coordinate. Read [CLI privacy](docs/CLI.md) and [security coverage](docs/SECURITY_MODEL.md). The core and Action are Apache-2.0; hosted implementation is not included here.

DriftSeal does not guarantee software security. A clean result means only that no material issue or drift was detected by the active ruleset and available coverage.

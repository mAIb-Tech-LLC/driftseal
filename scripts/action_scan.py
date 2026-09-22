"""No shell interpolation of Action inputs and no target package installation."""

import json
import os
from pathlib import Path

from driftseal.diff import compare, sarif
from driftseal.runner import isolated_scan

report = isolated_scan({"kind": "local", "target": str(Path(os.environ.get("DRIFTSEAL_TARGET", ".")).absolute())})
baseline = Path(os.environ.get("DRIFTSEAL_BASELINE", ".driftseal-baseline.json"))
findings = compare(json.loads(baseline.read_text()), report) if baseline.is_file() else report["findings"]
directory = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "driftseal-results"
directory.mkdir(parents=True, exist_ok=True)
(directory / "report.json").write_text(json.dumps(report, indent=2))
(directory / "result.json").write_text(json.dumps({"findings": findings}, indent=2))
(directory / "result.sarif").write_text(json.dumps(sarif(findings), indent=2))
if os.getenv("GITHUB_OUTPUT"):
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        out.write(f"result={directory}/result.json\nsarif={directory}/result.sarif\n")
if os.getenv("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
        out.write(f"## DriftSeal\n\n{len(findings)} deterministic findings. Target code was not executed.\n\n")
        for item in findings[:30]:
            out.write(f"- **{item['severity'].upper()}** `{item['type']}`\n")
        out.write("\nReview the JSON/SARIF artifact for evidence. A clean scan does not guarantee security.\n")
levels = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
threshold = os.environ.get("DRIFTSEAL_FAIL_ON", "critical")
if threshold not in levels:
    raise SystemExit("Invalid fail-on severity")
raise SystemExit(1 if any(levels[f["severity"]] >= levels[threshold] for f in findings) else 0)

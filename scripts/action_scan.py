"""No shell interpolation of Action inputs and no target package installation."""

import json
import os
from pathlib import Path

from driftseal.conversion import watch_url
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
        out.write(
            "\nA point-in-time scan is not continuous trust monitoring. Want to know when this changes later?\n\n[WATCH THIS COMPONENT]("
            + watch_url(source="github-action")
            + ") · [Approve a baseline](https://drift.maib.io/docs/github-action?source=github-action)\n\nLocal source and detailed findings are never uploaded to DriftSeal. Anonymous stage reporting is disabled unless explicitly enabled. The link opens the public-component workflow; private repositories stay local.\n"
        )
levels = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
if os.getenv("DRIFTSEAL_TELEMETRY", "false").lower() == "true":
    # Explicit opt-in; no repository identity, source, coordinate or findings leave CI.
    import re
    import urllib.request
    import uuid

    installation = os.getenv("DRIFTSEAL_INSTALLATION_ID", "")
    if not re.fullmatch(r"[a-f0-9-]{36}", installation):
        installation = None
    try:
        payload = {
            "run_id": str(uuid.uuid4()),
            "installation_id": installation,
            "baseline_compared": baseline.is_file(),
        }
        request = urllib.request.Request(
            "https://drift.maib.io/api/action-events",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5):
            pass
    except Exception:
        pass  # Acquisition telemetry never changes a security check's result.
threshold = os.environ.get("DRIFTSEAL_FAIL_ON", "critical")
if threshold not in levels:
    raise SystemExit("Invalid fail-on severity")
raise SystemExit(1 if any(levels[f["severity"]] >= levels[threshold] for f in findings) else 0)

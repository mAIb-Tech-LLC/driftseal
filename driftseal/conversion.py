"""A user-clicked handoff; no automatic telemetry or private-source upload."""

from urllib.parse import urlencode

BASELINE_DOCS = "https://github.com/mAIb-Tech-LLC/driftseal#cli-approve-a-baseline-then-review-the-diff"


def watch_url(report=None, source="cli"):
    params = {"source": source}
    if report and report.get("target_type") in {"npm", "pypi", "github", "mcp"}:
        params.update(kind=report["target_type"], target=report["identifier"])
    return "https://drift.maib.io/?" + urlencode(params) + "#scanner"

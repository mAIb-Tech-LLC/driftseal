from .rules import HIGH_IMPACT, finding
from .safety import Rejected, digest

DRIFT_TYPES = [
    "ARTIFACT_DRIFT",
    "VERSION_DRIFT",
    "SOURCE_COMMIT_DRIFT",
    "TOOL_ADDED",
    "TOOL_REMOVED",
    "TOOL_DESCRIPTION_DRIFT",
    "TOOL_SCHEMA_DRIFT",
    "TOOL_CAPABILITY_EXPANSION",
    "TOOL_CAPABILITY_REDUCTION",
    "PERMISSION_EXPANSION",
    "FILESYSTEM_SCOPE_EXPANSION",
    "NETWORK_SCOPE_EXPANSION",
    "SHELL_CAPABILITY_ADDED",
    "SENSITIVE_PATH_ACCESS_ADDED",
    "CREDENTIAL_ACCESS_ADDED",
    "NEW_INSTALL_SCRIPT",
    "DEPENDENCY_DRIFT",
    "KNOWN_VULNERABILITY_ADDED",
    "UNPINNED_DEPENDENCY_ADDED",
    "REMOTE_SOURCE_CHANGED",
    "HIDDEN_INSTRUCTION_ADDED",
    "ENCODED_PAYLOAD_INDICATOR_ADDED",
    "CROSS_TOOL_NAME_COLLISION",
    "UNKNOWN_MATERIAL_CHANGE",
]


def compare(old, new):
    if old.get("identifier") != new.get("identifier") or old.get("target_type") != new.get("target_type"):
        raise Rejected("Baselines must identify the same target")
    findings = []

    def add(kind, before, after, path, why, severity="medium"):
        findings.append(finding(kind, before, after, path, why, severity))

    for field, kind, severity in [
        ("artifact_sha256", "ARTIFACT_DRIFT", "info"),
        ("resolved_version", "VERSION_DRIFT", "info"),
        ("source_commit_sha", "SOURCE_COMMIT_DRIFT", "info"),
    ]:
        if old.get(field) != new.get(field):
            add(kind, old.get(field), new.get(field), field, "The approved component identity has changed.", severity)
    # Version-specific archive URLs are already represented by VERSION_DRIFT.
    if old.get("source_url") != new.get("source_url") and old.get("resolved_version") == new.get("resolved_version"):
        add(
            "REMOTE_SOURCE_CHANGED",
            old.get("source_url"),
            new.get("source_url"),
            "source_url",
            "The component is now retrieved from a different source.",
            "high",
        )
    if old.get("ruleset_version") != new.get("ruleset_version") or old.get("scanner_version") != new.get(
        "scanner_version"
    ):
        add(
            "UNKNOWN_MATERIAL_CHANGE",
            old.get("ruleset_version"),
            new.get("ruleset_version"),
            "ruleset",
            "Scanner coverage changed; review the new scan before renewing approval.",
        )
    a = {t["name"]: t for t in old.get("tools", [])}
    b = {t["name"]: t for t in new.get("tools", [])}
    for name in sorted(set(a) | set(b)):
        if name not in a:
            add("TOOL_ADDED", None, b[name], name, "A new tool expands the available agent surface.", "high")
        elif name not in b:
            add("TOOL_REMOVED", a[name], None, name, "An approved tool is no longer advertised.", "info")
        else:
            for field, kind, severity in [
                ("description", "TOOL_DESCRIPTION_DRIFT", "medium"),
                ("inputSchema", "TOOL_SCHEMA_DRIFT", "high"),
                ("annotations", "UNKNOWN_MATERIAL_CHANGE", "medium"),
            ]:
                if a[name].get(field) != b[name].get(field):
                    add(
                        kind,
                        a[name].get(field),
                        b[name].get(field),
                        f"tools/{name}/{field}",
                        "The advertised tool contract changed after approval.",
                        severity,
                    )
            before, after = set(a[name].get("capabilities", [])), set(b[name].get("capabilities", []))
            if after - before:
                add(
                    "TOOL_CAPABILITY_EXPANSION",
                    sorted(before),
                    sorted(after),
                    name,
                    "This tool advertises or indicates additional capabilities.",
                    "critical" if (after - before) & HIGH_IMPACT else "high",
                )
            if before - after:
                add(
                    "TOOL_CAPABILITY_REDUCTION",
                    sorted(before),
                    sorted(after),
                    name,
                    "Previously observed capabilities were removed.",
                    "info",
                )
    before, after = set(old.get("capabilities", [])), set(new.get("capabilities", []))
    for cap in sorted(after - before):
        kind = {"EXECUTE_COMMAND": "SHELL_CAPABILITY_ADDED", "READ_CREDENTIAL": "CREDENTIAL_ACCESS_ADDED"}.get(
            cap, "PERMISSION_EXPANSION"
        )
        add(
            kind,
            False,
            cap,
            "capabilities",
            "A new capability appeared after approval.",
            "critical" if cap in HIGH_IMPACT else "high",
        )
        if cap == "READ_CREDENTIAL":
            add(
                "SENSITIVE_PATH_ACCESS_ADDED",
                False,
                cap,
                "capabilities",
                "Sensitive credential paths are newly referenced.",
                "critical",
            )
    if before - after:
        add(
            "TOOL_CAPABILITY_REDUCTION",
            sorted(before),
            sorted(after),
            "capabilities",
            "Capability indicators were removed.",
            "info",
        )
    for field, kind in [
        ("permissions", "PERMISSION_EXPANSION"),
        ("filesystem_scopes", "FILESYSTEM_SCOPE_EXPANSION"),
        ("network_scopes", "NETWORK_SCOPE_EXPANSION"),
    ]:
        if set(new.get(field, [])) - set(old.get(field, [])):
            add(
                kind,
                old.get(field, []),
                new.get(field, []),
                field,
                "New declared scopes or referenced destinations require review.",
                "high",
            )
    for script, value in new.get("install_scripts", {}).items():
        if old.get("install_scripts", {}).get(script) != value:
            add(
                "NEW_INSTALL_SCRIPT",
                old.get("install_scripts", {}).get(script),
                value,
                script,
                "New or modified lifecycle code may execute at installation.",
                "high",
            )
    if old.get("dependencies") != new.get("dependencies"):
        add(
            "DEPENDENCY_DRIFT",
            old.get("dependencies", {}),
            new.get("dependencies", {}),
            "dependencies",
            "The dependency graph declarations changed.",
        )
        for dep, version in new.get("dependencies", {}).items():
            import re

            if old.get("dependencies", {}).get(dep) != version and not re.fullmatch(
                r"(?:==)?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version
            ):
                add(
                    "UNPINNED_DEPENDENCY_ADDED",
                    old.get("dependencies", {}).get(dep),
                    version,
                    dep,
                    "A dependency can resolve to different content without a manifest edit.",
                    "high",
                )
    previous = {digest(v) for v in old.get("vulnerabilities", [])}
    for vuln in new.get("vulnerabilities", []):
        if digest(vuln) not in previous:
            add(
                "KNOWN_VULNERABILITY_ADDED",
                None,
                vuln,
                "vulnerabilities",
                "New vulnerability metadata is associated with this component.",
                "high",
            )
    previous = {(v["type"], v["path"]) for v in old.get("indicators", [])}
    for indicator in new.get("indicators", []):
        if (indicator["type"], indicator["path"]) not in previous:
            kind = {
                "HIDDEN_INSTRUCTION": "HIDDEN_INSTRUCTION_ADDED",
                "ENCODED_PAYLOAD_INDICATOR": "ENCODED_PAYLOAD_INDICATOR_ADDED",
            }.get(indicator["type"], "UNKNOWN_MATERIAL_CHANGE")
            add(
                kind,
                None,
                indicator["type"],
                indicator["path"],
                "A new suspicious static indicator requires review.",
                "high",
            )
    old_collisions = {f["new_value"] for f in old.get("findings", []) if f["type"] == "CROSS_TOOL_NAME_COLLISION"}
    for f in new.get("findings", []):
        if f["type"] == "CROSS_TOOL_NAME_COLLISION" and f["new_value"] not in old_collisions:
            findings.append(f)
    changed_files = sorted(
        k
        for k in set(old.get("file_hashes", {})) | set(new.get("file_hashes", {}))
        if old.get("file_hashes", {}).get(k) != new.get("file_hashes", {}).get(k)
    )
    # A source change with no explained semantic difference must remain visible.
    non_json = [p for p in changed_files if not p.endswith((".json", ".md", ".txt"))]
    if non_json and not any(f["severity"] in {"high", "critical"} for f in findings):
        add(
            "UNKNOWN_MATERIAL_CHANGE",
            "approved file hashes",
            non_json[:100],
            "files",
            "Source changed beyond the tool surface; static coverage cannot determine its effect.",
        )
    return findings


def sarif(findings):
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "DriftSeal", "version": "0.1.0"}},
                "results": [
                    {
                        "ruleId": f["type"],
                        "level": "error"
                        if f["severity"] in {"critical", "high"}
                        else "note"
                        if f["severity"] == "info"
                        else "warning",
                        "message": {"text": f["why_it_matters"] + " " + f["recommendation"]},
                        "properties": {
                            "severity": f["severity"],
                            "affected_path": f["affected_path"],
                            "evidence": f["evidence"],
                        },
                    }
                    for f in findings
                ],
            }
        ],
    }

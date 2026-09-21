import base64
import hashlib
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import RULESET, __version__
from .archive import relevant, unpack
from .rules import CAPABILITIES, finding, inspect_text
from .safety import MAX_EXTRACTED, MAX_FILE, MAX_FILES, MAX_JSON, Rejected, canonical, digest, fetch, parse_json


def redact(value, key=""):
    """Never include env values, credential fields, private keys or URL credentials in evidence."""
    if re.search(r"(?:secret|password|token|api.?key|private.?key|authorization|cookie)", key, re.I):
        return "[REDACTED]"
    if key.lower() == "env" and isinstance(value, dict):
        return {k: "[REDACTED]" for k in value}
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(
            r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", value
        )
        value = re.sub(r"\b(?:sk_(?:live|test)_|gh[pousr]_|AKIA)[A-Za-z0-9_/-]{12,}", "[REDACTED]", value)
        value = re.sub(r"(?i)(?:bearer\s+)[A-Za-z0-9._~+/-]+=*", "[REDACTED]", value)
        value = re.sub(r"(?i)((?:password|secret|api[_-]?key|token)\s*[=:]\s*)[^\s,;\"']+", r"\1[REDACTED]", value)
        value = re.sub(r"https?://[^\s/]+@", "https://[REDACTED]@", value)
        return value[:16000]
    return value


def blank(target_type, identifier):
    return {
        "schema_version": 1,
        "id": str(uuid.uuid4()),
        "organisation_id": None,
        "user_id": None,
        "target_type": target_type,
        "identifier": identifier,
        "resolved_version": None,
        "source_url": None,
        "source_commit_sha": None,
        "artifact_sha256": None,
        "integrity": {},
        "package_metadata": {},
        "dependencies": {},
        "tools": [],
        "tool_surface_hash": None,
        "capabilities": [],
        "permissions": [],
        "filesystem_scopes": [],
        "network_scopes": [],
        "install_scripts": {},
        "indicators": [],
        "vulnerabilities": [],
        "findings": [],
        "file_hashes": {},
        "scanner_version": __version__,
        "ruleset_version": RULESET,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "coverage": {
            "level": "static",
            "limitations": [
                "No target execution; computed tools and runtime behavior are not observed.",
                "Capability indicators are heuristic and do not prove reachability.",
            ],
        },
        "metrics": {},
    }


def analyze(files, baseline=None):
    b = baseline or blank("manifest", "pasted-manifest")
    caps, tool_names = set(), set()
    for path, text in sorted(files.items()):
        b["file_hashes"][path] = digest(text.encode())
        found, risks = inspect_text(text, path)
        caps.update(found)
        b["findings"].extend(risks)
        b["indicators"].extend({"type": f["type"], "path": path} for f in risks)
        for domain in re.findall(r"https?://([a-zA-Z0-9.-]+)", text):
            if domain not in b["network_scopes"]:
                b["network_scopes"].append(domain.lower())
        if path.endswith(".json"):
            try:
                obj = parse_json(text)
            except Rejected:
                b["coverage"]["limitations"].append(f"JSON could not be analysed: {path}")
                continue
            if not isinstance(obj, dict):
                continue
            if path.endswith("package.json"):
                b["package_metadata"] = redact(
                    {k: obj.get(k) for k in ["name", "version", "license", "description", "repository"]}
                )
                for field in ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]:
                    if isinstance(obj.get(field), dict):
                        for name, version in obj[field].items():
                            b["dependencies"][f"{path}:{field}:{name}"] = str(version)[:500]
                for name in ["preinstall", "install", "postinstall", "prepare"]:
                    script = obj.get("scripts", {}).get(name) if isinstance(obj.get("scripts", {}), dict) else None
                    if script:
                        b["install_scripts"][f"{path}:{name}"] = {
                            "sha256": digest(str(script).encode()),
                            "present": True,
                        }
                        b["findings"].append(
                            finding(
                                "INSTALL_SCRIPT",
                                None,
                                name,
                                path,
                                "Lifecycle scripts execute when installed; DriftSeal does not execute them.",
                                "medium",
                            )
                        )
            tools = obj.get(
                "tools", obj.get("result", {}).get("tools", []) if isinstance(obj.get("result"), dict) else []
            )
            if tools and not isinstance(tools, list):
                raise Rejected("tools must be an array")
            if len(tools) > 250:
                raise Rejected("Tool count exceeds 250")
            for tool in tools:
                if (
                    not isinstance(tool, dict)
                    or not isinstance(tool.get("name"), str)
                    or not tool["name"]
                    or len(tool["name"]) > 128
                ):
                    raise Rejected("Invalid tool definition")
                t = {
                    "name": tool["name"],
                    "description": re.sub(r"\s+", " ", str(tool.get("description", ""))).strip(),
                    "inputSchema": tool.get("inputSchema", {}),
                    "annotations": tool.get("annotations", {}),
                    "path": path,
                }
                t["capabilities"] = inspect_text(canonical(tool), path)[0]
                declared = tool.get("capabilities", [])
                if isinstance(declared, list):
                    t["capabilities"] = sorted(
                        set(t["capabilities"]) | {x for x in declared if isinstance(x, str) and x in CAPABILITIES}
                    )
                caps.update(t["capabilities"])
                if t["name"] in tool_names:
                    b["findings"].append(
                        finding(
                            "CROSS_TOOL_NAME_COLLISION",
                            None,
                            t["name"],
                            path,
                            "Duplicate tool names make selection ambiguous.",
                            "high",
                        )
                    )
                tool_names.add(t["name"])
                b["tools"].append(redact(t))
            for key in ["permissions", "filesystem_scopes"]:
                if isinstance(obj.get(key), list):
                    b[key].extend(str(x)[:300] for x in obj[key] if isinstance(x, str))
            servers = obj.get("mcpServers", {})
            if isinstance(servers, dict):
                for name, server in servers.items():
                    if isinstance(server, dict) and isinstance(server.get("env"), dict) and server["env"]:
                        caps.add("READ_ENV")
    b["capabilities"] = sorted(caps)
    for key in ["network_scopes", "permissions", "filesystem_scopes"]:
        b[key] = sorted(set(b[key]))
    b["tools"] = sorted(b["tools"], key=lambda t: (t["name"], t["path"]))
    b["tool_surface_hash"] = digest(b["tools"])
    if b["artifact_sha256"] is None:
        b["artifact_sha256"] = digest(b["file_hashes"])
    for cap in b["capabilities"]:
        if cap in {"EXECUTE_COMMAND", "READ_CREDENTIAL", "READ_ENV", "NETWORK_ARBITRARY"}:
            b["findings"].append(
                finding(
                    "CAPABILITY_INDICATOR",
                    None,
                    cap,
                    "component",
                    "Static content indicates a capability that needs review before approval.",
                    "high",
                    confidence="medium",
                )
            )
    b["coverage"]["analysed_files"] = len(files)
    b["coverage"]["tool_count"] = len(b["tools"])
    return redact(b)


def scan_manifest(text):
    obj = parse_json(text)
    if not isinstance(obj, dict):
        raise Rejected("A JSON object is required")
    return analyze({"manifest.json": canonical(obj)})


def scan_local(path):
    root = Path(path)
    if root.is_symlink():
        raise Rejected("Symlink target forbidden")
    if root.is_file() and root.suffix.lower() in {".zip", ".gz", ".tgz", ".whl"}:
        if root.stat().st_size > 12 * 1024 * 1024:
            raise Rejected("Artifact exceeds limit")
        data = root.read_bytes()
        files, metrics = unpack(data)
        b = blank("local", root.name)
        b["artifact_sha256"], b["metrics"] = digest(data), metrics
        return analyze(files, b)
    files, total, count = {}, 0, 0
    candidates = [root] if root.is_file() else root.rglob("*")
    for p in candidates:
        relative = p.name if root.is_file() else p.relative_to(root).as_posix()
        if any(part in {".git", ".venv", "node_modules", ".driftseal", "__pycache__"} for part in Path(relative).parts):
            continue
        count += 1
        if count > MAX_FILES:
            raise Rejected("Local file count limit exceeded")
        if p.is_symlink() or not p.is_file() or not relevant(relative):
            continue
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(p, flags), "rb") as handle:
            data = handle.read(MAX_FILE + 1)
        total += len(data)
        if len(data) > MAX_FILE or total > MAX_EXTRACTED:
            raise Rejected("Local content limit exceeded")
        if b"\x00" not in data:
            files[relative] = data.decode("utf-8", errors="replace")
    if not files:
        raise Rejected("No supported text files found")
    return analyze(files, blank("local", root.name))


def verify_integrity(data, integrity):
    for item in integrity.split():
        algorithm, _, expected = item.partition("-")
        if algorithm in {"sha512", "sha256", "sha384", "sha1"}:
            actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
            if actual != expected:
                raise Rejected("Registry artifact digest mismatch")
            return algorithm
    raise Rejected("No supported registry digest")


def scan_remote(kind, identifier):
    started = time.monotonic()
    b = blank(kind, identifier)
    if kind == "npm":
        if (
            not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+(?:@[a-zA-Z0-9._+-]+)?", identifier)
            or len(identifier) > 220
        ):
            raise Rejected("Invalid npm package coordinate")
        name, sep, version = identifier.rpartition("@")
        if not sep or not name:
            name, version = identifier, "latest"
        url = f"https://registry.npmjs.org/{quote(name, safe='')}/{quote(version, safe='')}"
        meta = parse_json(fetch(url, allowed_hosts={"registry.npmjs.org"}, limit=MAX_JSON))
        artifact_url = meta["dist"]["tarball"]
        data = fetch(artifact_url, allowed_hosts={"registry.npmjs.org"})
        integrity = meta["dist"].get("integrity")
        if not integrity and meta["dist"].get("shasum"):
            integrity = "sha1-" + base64.b64encode(bytes.fromhex(meta["dist"]["shasum"])).decode()
        verify_integrity(data, integrity or "")
        b.update(
            resolved_version=meta["version"],
            source_url=artifact_url,
            integrity={"registry": integrity, "verified": True},
        )
    elif kind == "pypi":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:==[A-Za-z0-9.+!-]+)?", identifier) or len(identifier) > 220:
            raise Rejected("Invalid PyPI coordinate")
        name, _, version = identifier.partition("==")
        url = f"https://pypi.org/pypi/{quote(name)}/{quote(version) + '/' if version else ''}json"
        meta = parse_json(fetch(url, allowed_hosts={"pypi.org"}, limit=MAX_JSON))
        artifacts = sorted(
            meta.get("urls", []),
            key=lambda x: (
                0 if x.get("filename", "").endswith("-none-any.whl") else 1 if x.get("packagetype") == "sdist" else 2,
                x.get("filename", ""),
            ),
        )
        if not artifacts:
            raise Rejected("No supported PyPI artifact")
        artifact = artifacts[0]
        data = fetch(artifact["url"], allowed_hosts={"files.pythonhosted.org"})
        if digest(data) != artifact["digests"].get("sha256"):
            raise Rejected("Registry artifact digest mismatch")
        b.update(
            resolved_version=meta["info"]["version"],
            source_url=artifact["url"],
            integrity={"sha256": digest(data), "verified": True},
        )
        b["dependencies"] = {str(i): x for i, x in enumerate(meta["info"].get("requires_dist") or [])}
        b["package_metadata"] = {k: meta["info"].get(k) for k in ["name", "version", "license", "summary"]}
    elif kind == "github":
        match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", identifier)
        if not match:
            raise Rejected("Use a public github.com owner/repository URL")
        owner, repo = match.groups()
        meta = parse_json(
            fetch(
                f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD",
                allowed_hosts={"api.github.com"},
                limit=MAX_JSON,
            )
        )
        sha = meta["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise Rejected("Invalid source commit")
        b.update(source_commit_sha=sha, source_url=identifier)
        data = fetch(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}", allowed_hosts={"codeload.github.com"})
        b["integrity"] = {"verified": False, "reason": "GitHub source archive has no independent registry digest"}
    elif kind == "mcp":
        # HTTP metadata only, no initialization side effects or target tool invocation.
        payload = canonical({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
        raw = fetch(
            identifier,
            limit=MAX_JSON,
            method="POST",
            body=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            redirects=0,
        )
        obj = parse_json(raw)
        if (
            not isinstance(obj, dict)
            or not isinstance(obj.get("result"), dict)
            or not isinstance(obj["result"].get("tools"), list)
        ):
            raise Rejected("Endpoint does not provide stateless JSON tools/list metadata; export a manifest instead")
        if obj["result"].get("nextCursor"):
            raise Rejected("Paginated metadata unsupported; export a complete manifest")
        b.update(source_url=identifier, artifact_sha256=digest(raw))
        b["coverage"]["level"] = "tool-metadata-only"
        result = analyze({"manifest.json": canonical(obj)}, b)
        result["metrics"]["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result
    else:
        raise Rejected("Unsupported target type")
    b["artifact_sha256"] = digest(data)
    files, metrics = unpack(data)
    if kind == "github":
        files = {path.split("/", 1)[1] if "/" in path else path: value for path, value in files.items()}
    b["metrics"] = metrics
    if kind in {"npm", "pypi"}:
        try:
            query = {
                "package": {"name": name, "ecosystem": "npm" if kind == "npm" else "PyPI"},
                "version": b["resolved_version"],
            }
            osv = parse_json(
                fetch(
                    "https://api.osv.dev/v1/query",
                    allowed_hosts={"api.osv.dev"},
                    method="POST",
                    body=canonical(query).encode(),
                    headers={"Content-Type": "application/json"},
                    redirects=0,
                    limit=MAX_JSON,
                )
            )
            b["vulnerabilities"] = [
                {"id": v["id"], "aliases": v.get("aliases", []), "modified": v.get("modified")}
                for v in osv.get("vulns", [])
                if not v.get("withdrawn")
            ]
            b["coverage"]["vulnerability_lookup"] = (
                "OSV direct package/version; transitive vulnerabilities not resolved"
            )
        except Exception:
            b["coverage"]["limitations"].append(
                "OSV direct-package vulnerability lookup unavailable; empty metadata does not mean no known vulnerabilities."
            )
    else:
        b["coverage"]["limitations"].append("Vulnerability lookup applies only to registry package versions.")
    result = analyze(files, b)
    result["metrics"]["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def private_summary(baseline):
    """Explicit opt-in cloud upload format; no source, descriptions, schemas or raw paths."""
    keys = [
        "schema_version",
        "target_type",
        "identifier",
        "resolved_version",
        "artifact_sha256",
        "tool_surface_hash",
        "capabilities",
        "scanner_version",
        "ruleset_version",
        "scanned_at",
    ]
    result = {k: baseline[k] for k in keys}
    result["tools"] = [
        {"name_hash": digest(t["name"]), "surface_hash": digest(t), "capabilities": t["capabilities"]}
        for t in baseline["tools"]
    ]
    result["findings"] = [
        {"type": f["type"], "severity": f["severity"], "confidence": f["confidence"]} for f in baseline["findings"]
    ]
    return result

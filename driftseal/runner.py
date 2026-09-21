"""Bounded subprocess protocol. Only DriftSeal code is launched, never a target executable."""

import json
import os
import subprocess
import sys

from .safety import MAX_DOWNLOAD, MAX_SCAN_SECONDS, Rejected, canonical


def isolated_scan(request):
    encoded = canonical(request).encode()
    if len(encoded) > MAX_DOWNLOAD * 2:
        raise Rejected("Scan request exceeds limit")
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG") if k in os.environ}
    try:
        run = subprocess.run(
            [sys.executable, "-m", "driftseal.runner"],
            input=encoded,
            capture_output=True,
            timeout=MAX_SCAN_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise Rejected("Scan exceeded 45 seconds") from exc
    if run.returncode or len(run.stdout) > 8 * 1024 * 1024:
        raise Rejected("Scanner process rejected input or exceeded resource limits")
    result = json.loads(run.stdout)
    if "error" in result:
        raise Rejected(result["error"])
    return result


def main():
    import base64
    import resource

    from .archive import unpack
    from .safety import digest
    from .scanner import analyze, blank, scan_manifest, scan_remote

    resource.setrlimit(resource.RLIMIT_CPU, (35, 35))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if sys.platform == "linux":
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
    try:
        req = json.loads(sys.stdin.buffer.read(MAX_DOWNLOAD * 2 + 1))
        if req["kind"] == "manifest":
            result = scan_manifest(req["content"])
        elif req["kind"] == "archive":
            data = base64.b64decode(req["content"], validate=True)
            files, metrics = unpack(data)
            b = blank("archive", "uploaded-archive")
            b.update(artifact_sha256=digest(data), metrics=metrics)
            result = analyze(files, b)
        else:
            result = scan_remote(req["kind"], req["target"])
        print(canonical(result))
    except Rejected as exc:
        print(canonical({"error": str(exc)}))
    except Exception:
        print(canonical({"error": "Unsupported or malformed component metadata"}))


if __name__ == "__main__":
    main()

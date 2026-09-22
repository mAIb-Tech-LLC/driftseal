import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import RULESET, __version__
from .diff import compare, sarif
from .runner import isolated_scan
from .safety import Rejected, canonical, verified_tls_context


def config_path():
    return Path(os.getenv("DRIFTSEAL_CONFIG_DIR", str(Path.home() / ".config" / "driftseal"))) / "credentials.json"


def cloud(method, path, payload=None):
    from urllib.request import Request

    p = config_path()
    if not p.exists():
        raise Rejected("Run driftseal login first")
    config = json.loads(p.read_text())
    from urllib.parse import urlsplit

    url = config["url"]
    parsed = urlsplit(url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}):
        raise Rejected("Cloud credentials require HTTPS")
    request = Request(
        url + path,
        data=canonical(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + config["token"], "Content-Type": "application/json"},
        method=method,
    )
    # No redirect may carry the account token to another endpoint.
    from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise Rejected("Cloud redirect rejected")

    with build_opener(NoRedirect, HTTPSHandler(context=verified_tls_context())).open(request, timeout=30) as response:
        return json.load(response)


def scan_target(target, kind=None):
    if target == "-":
        return isolated_scan({"kind": "manifest", "content": sys.stdin.read(1024 * 1024 + 1)})
    if Path(target).exists():
        return isolated_scan({"kind": "local", "target": str(Path(target).absolute())})
    if kind:
        return isolated_scan({"kind": kind, "target": target})
    if target.startswith("https://github.com/"):
        return isolated_scan({"kind": "github", "target": target})
    if target.startswith("pypi:"):
        return isolated_scan({"kind": "pypi", "target": target[5:]})
    return isolated_scan({"kind": "npm", "target": target.removeprefix("npm:")})


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="driftseal", description="Deterministic trust drift evidence. Target code is never executed."
    )
    parser.add_argument(
        "command", choices=["scan", "baseline", "diff", "watch", "status", "login", "logout", "version"]
    )
    parser.add_argument("target", nargs="?")
    parser.add_argument("current", nargs="?")
    parser.add_argument("--kind", choices=["npm", "pypi", "github", "mcp"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical", "none"], default="none")
    parser.add_argument("--output", "-o")
    parser.add_argument("--url", default="https://drift.maib.io")
    args = parser.parse_args(argv)
    try:
        findings = []
        if args.command == "version":
            result = {"version": __version__, "ruleset": RULESET}
        elif args.command in {"scan", "baseline"}:
            result = scan_target(args.target or ".", args.kind)
            findings = result["findings"]
            if args.command == "baseline":
                output = Path(args.output or ".driftseal-baseline.json")
                # Explicit approval, never silently overwrite an existing approved baseline.
                with output.open("x") as handle:
                    handle.write(canonical(result) + "\n")
                print(f"Baseline locked: {output}", file=sys.stderr)
                args.output = None
        elif args.command == "diff":
            if not args.target or not args.current:
                raise Rejected("Usage: driftseal diff BASELINE.json CURRENT.json")
            from .safety import parse_json

            old, new = parse_json(Path(args.target).read_bytes()), parse_json(Path(args.current).read_bytes())
            findings = compare(old, new)
            result = {
                "findings": findings,
                "ruleset_version": RULESET,
                "material_drift": any(f["severity"] not in {"info", "low"} for f in findings),
            }
        elif args.command == "login":
            from urllib.parse import urlsplit

            if urlsplit(args.url).scheme != "https" and args.url not in {
                "http://127.0.0.1:8150",
                "http://localhost:8150",
            }:
                raise Rejected("Use an HTTPS cloud URL")
            print(f"Sign in at {args.url}/dashboard and create a CLI token in Account.", file=sys.stderr)
            token = getpass.getpass("CLI token (hidden): ")
            if not token or len(token) > 200:
                raise Rejected("Invalid token")
            p = config_path()
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump({"url": args.url.rstrip("/"), "token": token}, out)
            os.chmod(p, 0o600)
            result = {"authenticated": cloud("GET", "/api/me")["authenticated"]}
        elif args.command == "logout":
            if config_path().exists():
                try:
                    cloud("POST", "/api/auth/logout", {})
                finally:
                    config_path().unlink()
            result = {"signed_out": True}
        elif args.command == "status":
            result = cloud("GET", "/api/dashboard")
        else:
            if not args.target:
                raise Rejected("Usage: driftseal watch PACKAGE (public registry targets only)")
            if Path(args.target).exists() or args.target == "-":
                raise Rejected(
                    "Private sources stay local. Use scan, baseline and diff; hosted watches require a public target."
                )
            kind = args.kind or (
                "github"
                if args.target.startswith("https://github.com/")
                else "pypi"
                if args.target.startswith("pypi:")
                else "npm"
            )
            target = args.target.removeprefix("pypi:").removeprefix("npm:")
            queued = cloud("POST", "/api/scans", {"kind": kind, "target": target})
            import time

            for _ in range(35):
                result = cloud("GET", "/api/scans/" + queued["id"])
                if result["status"] in {"failed", "completed"}:
                    break
                time.sleep(2)
            if result["status"] != "completed":
                raise Rejected("Cloud scan did not complete; inspect the dashboard")
            result = cloud("POST", "/api/monitors", {"scan_id": queued["id"]})
        if args.sarif:
            rendered = json.dumps(sarif(findings), indent=2)
        elif args.json or args.command in {"baseline", "diff", "status"}:
            rendered = json.dumps(result, indent=2)
        elif "findings" in result:
            rendered = f"DriftSeal {__version__} · ruleset {RULESET}\n" + "\n".join(
                f"{f['severity'].upper():8} {f['type']} · {f['affected_path']}\n  {f['why_it_matters']}"
                for f in findings
            )
            if not findings:
                rendered += f"\nNo material issue detected by DriftSeal ruleset {RULESET} within static coverage."
            rendered += "\nTarget code was not executed. A clean result is not a security guarantee."
        else:
            rendered = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)
        levels = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return 1 if any(levels[f["severity"]] >= levels[args.fail_on] for f in findings) else 0
    except Exception as exc:
        message = (
            str(exc)
            if isinstance(exc, (Rejected, FileExistsError))
            else "Operation failed; verify input, authentication and connectivity"
        )
        print(json.dumps({"error": message}) if args.json else "driftseal: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

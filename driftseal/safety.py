"""Hostile input primitives. No downloaded code is ever executed."""

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

MAX_DOWNLOAD = 12 * 1024 * 1024
MAX_EXTRACTED = 32 * 1024 * 1024
MAX_FILES = 1500
MAX_FILE = 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_DEPTH = 40
MAX_SCAN_SECONDS = 45


class Rejected(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256((value if isinstance(value, bytes) else canonical(value).encode())).hexdigest()


def parse_json(data):
    if len(data) > MAX_JSON:
        raise Rejected("Manifest exceeds 1 MiB")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result or key in {"__proto__", "prototype", "constructor"}:
                raise Rejected("Duplicate or reserved JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Rejected("Nonfinite JSON"))
        )
        todo = [(value, 0)]
        nodes = 0
        while todo:
            item, depth = todo.pop()
            nodes += 1
            if depth > MAX_DEPTH or nodes > 30000:
                raise Rejected("JSON structural limit exceeded")
            if isinstance(item, dict):
                todo.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                todo.extend((v, depth + 1) for v in item)
        return value
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise Rejected("Invalid or excessively nested JSON") from exc


def public_addresses(host, port=443):
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise Rejected("DNS resolution failed") from exc
    if not addresses:
        raise Rejected("No public address")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if (
            not ip.is_global
            or ip.is_multicast
            or (isinstance(ip, ipaddress.IPv6Address) and (ip.ipv4_mapped or ip.sixtofour or ip.teredo))
        ):
            raise Rejected("Private, local, reserved and transition addresses are forbidden")
    return addresses


def validate_url(url, allowed_hosts=None):
    if len(url) > 2048 or any(ord(c) < 33 for c in url) or "\\" in url:
        raise Rejected("Invalid URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise Rejected("Invalid URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise Rejected("Only public HTTPS on port 443 without credentials is supported")
    host = parsed.hostname.encode("idna").decode().lower()
    if allowed_hosts and host not in allowed_hosts:
        raise Rejected("Unexpected external host")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise Rejected("Local hostname forbidden")
    return parsed, host


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname, ip, timeout):
        # python.org macOS installations can lack their own CA file. Use the OS trust bundle, never disable verification.
        cafile = (
            "/etc/ssl/cert.pem"
            if sys.platform == "darwin"
            and not ssl.get_default_verify_paths().cafile
            and Path("/etc/ssl/cert.pem").is_file()
            else None
        )
        super().__init__(hostname, timeout=timeout, context=ssl.create_default_context(cafile=cafile))
        self.pinned_ip = ip

    def connect(self):
        # The connection uses precisely the validated address; TLS still validates the original hostname.
        raw = socket.create_connection((self.pinned_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def fetch(url, *, allowed_hosts=None, limit=MAX_DOWNLOAD, method="GET", body=None, headers=None, redirects=2):
    started = time.monotonic()
    for hop in range(redirects + 1):
        parsed, host = validate_url(url, allowed_hosts)
        addresses = public_addresses(host)
        conn = PinnedHTTPS(host, addresses[0], timeout=8)
        try:
            path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            request_headers = {
                "User-Agent": "DriftSeal/0.1 (+https://drift.maib.io/security)",
                "Accept-Encoding": "identity",
                **(headers or {}),
            }
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                # POST bodies/signatures must never be forwarded to another origin.
                if method != "GET" or hop == redirects:
                    raise Rejected("Redirect forbidden or limit exceeded")
                url = urljoin(url, response.getheader("Location", ""))
                continue
            if response.status < 200 or response.status >= 300:
                raise Rejected(f"Remote server returned HTTP {response.status}")
            if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
                raise Rejected("HTTP content compression is unsupported")
            length = response.getheader("Content-Length")
            if length and (not length.isdigit() or int(length) > limit):
                raise Rejected("Download exceeds limit")
            chunks, size = [], 0
            while True:
                if time.monotonic() - started > 25:
                    raise Rejected("Download time limit exceeded")
                chunk = response.read(min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise Rejected("Download exceeds limit")
            return b"".join(chunks)
        except (OSError, http.client.HTTPException) as exc:
            raise Rejected("Remote retrieval failed") from exc
        finally:
            conn.close()
    raise Rejected("Redirect limit exceeded")

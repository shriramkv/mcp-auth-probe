"""Minimal HTTP client on http.client: no redirects, full control over headers."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

MAX_BODY = 256 * 1024


class ProbeNetworkError(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    url: str = ""
    method: str = ""

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        vals = [v for k, v in self.headers if k.lower() == name]
        return ", ".join(vals) if vals else None

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class Client:
    timeout: float = 10.0
    insecure: bool = False
    extra_headers: Dict[str, str] = field(default_factory=dict)
    log: List[Response] = field(default_factory=list)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None) -> Response:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ProbeNetworkError("unsupported URL scheme: %r" % url)
        host = parts.hostname or ""
        port = parts.port
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        hdrs = {"User-Agent": "mcp-auth-probe"}
        hdrs.update(self.extra_headers)
        hdrs.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read(MAX_BODY)
            out = Response(resp.status, list(resp.getheaders()), raw.decode("utf-8", "replace"), url, method)
        except (OSError, socket.timeout, http.client.HTTPException, ssl.SSLError) as exc:
            raise ProbeNetworkError("%s %s failed: %s" % (method, url, exc))
        finally:
            conn.close()
        self.log.append(out)
        return out

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Response:
        h = {"Accept": "application/json"}
        h.update(headers or {})
        return self.request("GET", url, h)

    def post_json(self, url: str, payload: dict, headers: Optional[Dict[str, str]] = None) -> Response:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        h.update(headers or {})
        return self.request("POST", url, h, json.dumps(payload).encode("utf-8"))


def parse_www_authenticate(value: Optional[str]) -> Dict[str, Dict[str, str]]:
    """Parse a WWW-Authenticate header into {scheme_lower: {param: value}}.

    Handles quoted strings with commas and several challenges in one header.
    """
    out: Dict[str, Dict[str, str]] = {}
    if not value:
        return out
    i, n = 0, len(value)
    scheme = None
    while i < n:
        while i < n and value[i] in " ,\t":
            i += 1
        start = i
        while i < n and value[i] not in " =,\t":
            i += 1
        token = value[start:i]
        if not token:
            break
        j = i
        while j < n and value[j] in " \t":
            j += 1
        if j < n and value[j] == "=" and scheme is not None:
            j += 1
            while j < n and value[j] in " \t":
                j += 1
            if j < n and value[j] == '"':
                j += 1
                buf = []
                while j < n and value[j] != '"':
                    if value[j] == "\\" and j + 1 < n:
                        j += 1
                    buf.append(value[j])
                    j += 1
                j += 1
                val = "".join(buf)
            else:
                s = j
                while j < n and value[j] not in ",":
                    j += 1
                val = value[s:j].strip()
            out[scheme][token.lower()] = val
            i = j
        else:
            scheme = token.lower()
            out.setdefault(scheme, {})
            i = j
    return out

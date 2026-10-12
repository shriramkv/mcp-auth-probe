"""Two bundled MCP-over-HTTP servers for the demo and the tests.

``secure``: resource server and authorization server metadata done right.
``weak``:   the same endpoint with the mistakes seen in real deployments.

Each server hosts both the MCP endpoint (/mcp) and the authorization server
metadata (issuer /as) on one local port. They answer just enough of MCP
(initialize) to show whether a request got through; there is no real OAuth
flow behind them, tokens are fixed strings.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple
from urllib.parse import parse_qs, urlsplit

VALID_TOKEN = "demo-valid-token"
FOREIGN_TOKEN = "demo-token-for-another-resource"

_TRACEBACK = (
    'Traceback (most recent call last):\n  File "/srv/app/auth.py", line 42, in check\n'
    "    scheme, cred = header.split(' ')\nValueError: not enough values to unpack\n"
)


def _init_result(req_id):
    return {"jsonrpc": "2.0", "id": req_id, "result": {
        "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
        "serverInfo": {"name": "sample", "version": "1.0"}}}


class _Base(BaseHTTPRequestHandler):
    server_version = "sample-mcp"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    @property
    def base(self) -> str:
        host, port = self.server.server_address[:2]
        return "http://%s:%d" % (host, port)

    def send(self, status, body=None, headers=None, ctype="application/json"):
        data = b""
        if body is not None:
            data = (json.dumps(body) if not isinstance(body, str) else body).encode("utf-8")
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if data:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}


class SecureHandler(_Base):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/.well-known/oauth-protected-resource/mcp":
            return self.send(200, {
                "resource": self.base + "/mcp",
                "authorization_servers": [self.base + "/as"],
                "scopes_supported": ["mcp:tools"],
                "bearer_methods_supported": ["header"],
            })
        if path == "/.well-known/oauth-authorization-server/as":
            return self.send(200, {
                "issuer": self.base + "/as",
                "authorization_endpoint": self.base + "/as/authorize",
                "token_endpoint": self.base + "/as/token",
                "registration_endpoint": self.base + "/as/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "client_id_metadata_document_supported": True,
            })
        self.send(404, {"error": "not_found"})

    def _challenge(self, error=None):
        parts = ['resource_metadata="%s/.well-known/oauth-protected-resource/mcp"' % self.base,
                 'scope="mcp:tools"']
        if error:
            parts.append('error="%s"' % error)
        return {"WWW-Authenticate": "Bearer " + ", ".join(parts)}

    def do_POST(self):
        parts = urlsplit(self.path)
        body = self.read_body()
        if parts.path != "/mcp":
            return self.send(404, {"error": "not_found"})
        origin = self.headers.get("Origin")
        if origin and origin != self.base:
            return self.send(403, {"error": "forbidden_origin"})
        auth = self.headers.get("Authorization") or ""
        if not auth:
            return self.send(401, {"error": "unauthorized"}, self._challenge())
        scheme, _, cred = auth.partition(" ")
        if scheme.lower() != "bearer" or not cred.strip():
            return self.send(401, {"error": "invalid_request"}, self._challenge("invalid_request"))
        if cred.strip() != VALID_TOKEN:  # foreign-audience tokens land here too
            return self.send(401, {"error": "invalid_token"}, self._challenge("invalid_token"))
        self.send(200, _init_result(body.get("id")))


class WeakHandler(_Base):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/.well-known/oauth-protected-resource":
            return self.send(200, {
                "resource": "https://api.example.com/mcp",   # wrong resource
                "authorization_servers": [self.base + "/as"],
            })
        if path == "/.well-known/oauth-authorization-server/as":
            return self.send(200, {
                "issuer": "https://login.example.com",        # issuer mismatch
                "authorization_endpoint": "http://login.example.com/authorize",
                "token_endpoint": self.base + "/as/token",
                "response_types_supported": ["code", "token"],
                "grant_types_supported": ["authorization_code", "implicit", "password"],
                "code_challenge_methods_supported": ["plain"],
            })
        self.send(404, {"error": "not_found"})

    def do_POST(self):
        parts = urlsplit(self.path)
        body = self.read_body()
        if parts.path != "/mcp":
            return self.send(404, {"error": "not_found"})
        cors = {}
        origin = self.headers.get("Origin")
        if origin:  # reflects any origin, with credentials
            cors = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        qs = parse_qs(parts.query)
        auth = self.headers.get("Authorization") or ""
        if "access_token" in qs:
            return self.send(200, _init_result(body.get("id")), cors)
        if not auth:
            return self.send(401, {"error": "unauthorized"}, cors)   # no WWW-Authenticate
        if auth.startswith("Basic"):
            return self.send(500, _TRACEBACK, cors, ctype="text/plain")
        scheme, _, cred = auth.partition(" ")
        if not cred.strip():
            return self.send(401, {"error": "unauthorized"}, cors)
        # Accepts any bearer token: no signature, expiry or audience check.
        self.send(200, _init_result(body.get("id")), cors)


HANDLERS = {"secure": SecureHandler, "weak": WeakHandler}


def start(kind: str = "secure", host: str = "127.0.0.1", port: int = 0) -> Tuple[str, ThreadingHTTPServer]:
    """Start a sample server in a daemon thread. Returns (mcp_url, server)."""
    srv = ThreadingHTTPServer((host, port), HANDLERS[kind])
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    h, p = srv.server_address[:2]
    return "http://%s:%d/mcp" % (h, p), srv


def stop(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()

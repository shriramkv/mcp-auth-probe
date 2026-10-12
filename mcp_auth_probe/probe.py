"""The probe: run every authorization check against a remote MCP server.

Checks follow the MCP authorization specification (revision 2025-11-25) and the
standards it builds on: OAuth 2.1, RFC 9728 (protected resource metadata),
RFC 8414 (authorization server metadata), RFC 8707 (resource indicators) and
RFC 6750 (bearer token usage).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

from . import __version__
from .httpc import Client, ProbeNetworkError, Response, parse_www_authenticate

SPEC_REVISION = "2025-11-25"

PASS, FAIL, SKIP = "pass", "fail", "skip"

DISCOVERY = "discovery"
AS_METADATA = "as-metadata"
TOKENS = "token-handling"
TRANSPORT = "transport"
DIMENSIONS = {DISCOVERY: 0.30, AS_METADATA: 0.25, TOKENS: 0.30, TRANSPORT: 0.15}

EVIL_ORIGIN = "https://evil.mcp-auth-probe.invalid"

_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r'File "[^"]+\.py", line \d+'),
    re.compile(r"\bat [a-zA-Z_$][\w$.]*\([\w$]+\.java:\d+\)"),
    re.compile(r"\bat .+ \(.+\.(?:js|ts):\d+:\d+\)"),
    re.compile(r"panic: .+\n\s*goroutine \d+"),
    re.compile(r"System\.\w+Exception:"),
]


@dataclass
class Check:
    id: str
    dimension: str
    severity: str          # severity if failed
    status: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ProbeResult:
    url: str
    checks: List[Check] = field(default_factory=list)
    prm_url: Optional[str] = None
    prm: Optional[dict] = None
    as_url: Optional[str] = None
    as_metadata: Optional[dict] = None
    public: bool = False
    exchanges: int = 0

    def add(self, *args, **kw) -> Check:
        c = Check(*args, **kw)
        self.checks.append(c)
        return c


# --------------------------------------------------------------- URL helpers

def is_local(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def canonical(url: str) -> str:
    """Canonical resource URI: lowercase scheme/host, no default port, no fragment,
    no trailing slash (MCP authorization spec, Canonical Server URI)."""
    p = urlsplit(url.strip())
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    port = p.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    netloc = host + (":%d" % port if port else "")
    path = p.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, p.query, ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def prm_candidates(server_url: str) -> List[str]:
    p = urlsplit(server_url)
    base = urlunsplit((p.scheme, p.netloc, "", "", ""))
    path = p.path.rstrip("/")
    out = []
    if path:
        out.append(base + "/.well-known/oauth-protected-resource" + path)
    out.append(base + "/.well-known/oauth-protected-resource")
    return out


def as_candidates(issuer: str) -> List[str]:
    p = urlsplit(issuer)
    base = urlunsplit((p.scheme, p.netloc, "", "", ""))
    path = p.path.rstrip("/")
    if path:
        return [
            base + "/.well-known/oauth-authorization-server" + path,
            base + "/.well-known/openid-configuration" + path,
            base + path + "/.well-known/openid-configuration",
        ]
    return [base + "/.well-known/oauth-authorization-server", base + "/.well-known/openid-configuration"]


def with_query(url: str, params: Dict[str, str]) -> str:
    p = urlsplit(url)
    q = (p.query + "&" if p.query else "") + urlencode(params)
    return urlunsplit((p.scheme, p.netloc, p.path, q, p.fragment))


def initialize_payload() -> dict:
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": SPEC_REVISION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-auth-probe", "version": __version__},
        },
    }


def _fetch_json(client: Client, urls: List[str]):
    tried = []
    for u in urls:
        try:
            r = client.get(u)
        except ProbeNetworkError as exc:
            tried.append("%s (%s)" % (u, exc))
            continue
        doc = r.json() if r.status == 200 else None
        if isinstance(doc, dict):
            return u, doc, tried
        tried.append("%s (HTTP %d)" % (u, r.status))
    return None, None, tried


def _status_word(r: Response) -> str:
    return "HTTP %d" % r.status


# --------------------------------------------------------------- the probe

def probe(url: str, client: Optional[Client] = None, token: Optional[str] = None,
          foreign_token: Optional[str] = None, expect_public: bool = False) -> ProbeResult:
    client = client or Client()
    res = ProbeResult(url=url)
    bad_token = "mcp-auth-probe-invalid-" + secrets.token_hex(12)

    def call(headers=None, target=None):
        return client.post_json(target or url, initialize_payload(), headers or {})

    # ---- transport: HTTPS
    if urlsplit(url).scheme == "https":
        res.add("server-https", TRANSPORT, "critical", PASS, "MCP endpoint is served over HTTPS")
    elif is_local(url):
        res.add("server-https", TRANSPORT, "critical", PASS, "MCP endpoint is HTTP on localhost",
                "plain HTTP is acceptable only for local development")
    else:
        res.add("server-https", TRANSPORT, "critical", FAIL, "MCP endpoint is served over plain HTTP",
                "tokens would travel in clear text; serve the endpoint over HTTPS")

    # ---- discovery: unauthenticated request
    unauth = call()
    if unauth.ok:
        res.public = True
        if expect_public:
            res.add("unauthenticated-rejected", DISCOVERY, "high", SKIP,
                    "Server accepted an unauthenticated request (expected: --expect-public)")
        else:
            res.add("unauthenticated-rejected", DISCOVERY, "high", FAIL,
                    "Server accepted an unauthenticated request",
                    "%s to initialize without a token. If the server is meant to be public, run with "
                    "--expect-public; otherwise authorization is not enforced." % _status_word(unauth))
    elif unauth.status == 401:
        res.add("unauthenticated-rejected", DISCOVERY, "high", PASS,
                "Unauthenticated request rejected with 401")
    elif unauth.status == 403:
        res.add("unauthenticated-rejected", DISCOVERY, "medium", FAIL,
                "Unauthenticated request rejected with 403 instead of 401",
                "a missing token is 401 Unauthorized; clients only start discovery on 401")
    else:
        res.add("unauthenticated-rejected", DISCOVERY, "high", FAIL,
                "Unexpected response to an unauthenticated request", _status_word(unauth))

    if res.public and expect_public:
        res.exchanges = len(client.log)
        return res

    challenge = parse_www_authenticate(unauth.header("WWW-Authenticate")) if unauth.status == 401 else {}
    bearer = challenge.get("bearer")
    if unauth.status == 401:
        if bearer is not None:
            res.add("www-authenticate-bearer", DISCOVERY, "high", PASS,
                    "401 carries a WWW-Authenticate Bearer challenge")
        else:
            res.add("www-authenticate-bearer", DISCOVERY, "high", FAIL,
                    "401 has no WWW-Authenticate Bearer challenge",
                    "RFC 6750 requires the challenge; clients use it to find the resource metadata")
    hint = (bearer or {}).get("resource_metadata")
    if unauth.status == 401:
        res.add("resource-metadata-hint", DISCOVERY, "low", PASS if hint else FAIL,
                "Challenge names resource_metadata" if hint else "Challenge does not name resource_metadata",
                "" if hint else "clients must fall back to probing well-known URIs")
        scope = (bearer or {}).get("scope")
        res.add("challenge-scope", DISCOVERY, "low", PASS if scope else FAIL,
                ("Challenge suggests scopes: %s" % scope) if scope else "Challenge has no scope parameter",
                "" if scope else "SHOULD include scope so clients request least privilege")

    # ---- discovery: protected resource metadata
    candidates = ([hint] if hint else []) + [u for u in prm_candidates(url) if u != hint]
    prm_url, prm, tried = _fetch_json(client, candidates)
    res.prm_url, res.prm = prm_url, prm
    if prm is None:
        res.add("prm-reachable", DISCOVERY, "critical", FAIL, "Protected resource metadata not found",
                "tried: " + "; ".join(tried))
    else:
        res.add("prm-reachable", DISCOVERY, "critical", PASS,
                "Protected resource metadata found", prm_url)
        if hint:
            hint_ok = prm_url == hint
            res.add("prm-hint-resolves", DISCOVERY, "medium", PASS if hint_ok else FAIL,
                    "resource_metadata URL resolves" if hint_ok else "resource_metadata URL is broken",
                    "" if hint_ok else "metadata came from a fallback well-known URI instead of " + hint)
        resource = prm.get("resource")
        if not isinstance(resource, str) or not resource:
            res.add("prm-resource-match", DISCOVERY, "high", FAIL, "Metadata has no resource identifier",
                    "RFC 9728 requires the resource field")
        else:
            accepted = {canonical(url)}
            if prm_url and prm_url.rstrip("/").endswith("/.well-known/oauth-protected-resource"):
                accepted.add(canonical(origin(url)))
            if canonical(resource) in accepted:
                res.add("prm-resource-match", DISCOVERY, "high", PASS,
                        "Metadata resource matches the server URL", resource)
            else:
                res.add("prm-resource-match", DISCOVERY, "high", FAIL,
                        "Metadata resource does not match the server URL",
                        "resource=%s, server=%s. Tokens are bound to the resource; a mismatch breaks "
                        "audience validation or lets one server's metadata vouch for another." % (resource, url))
        servers = prm.get("authorization_servers")
        if isinstance(servers, list) and servers and all(isinstance(s, str) for s in servers):
            res.add("prm-authorization-servers", DISCOVERY, "critical", PASS,
                    "Metadata lists %d authorization server(s)" % len(servers), ", ".join(servers))
        else:
            res.add("prm-authorization-servers", DISCOVERY, "critical", FAIL,
                    "Metadata lists no authorization_servers", "the MCP spec requires at least one")
            servers = []

        # ---- authorization server metadata (first listed server)
        if servers:
            issuer = servers[0]
            as_url, asm, tried = _fetch_json(client, as_candidates(issuer))
            res.as_url, res.as_metadata = as_url, asm
            _check_as(res, issuer, as_url, asm, tried)

    # ---- token handling
    r = call({"Authorization": "Bearer " + bad_token})
    _expect_rejected(res, "invalid-token-rejected", r, "an invalid bearer token")
    if r.status == 401:
        ch = parse_www_authenticate(r.header("WWW-Authenticate")).get("bearer") or {}
        err = ch.get("error")
        res.add("invalid-token-error", TOKENS, "low", PASS if err == "invalid_token" else FAIL,
                "401 for a bad token says error=\"invalid_token\"" if err == "invalid_token"
                else "401 for a bad token lacks error=\"invalid_token\"",
                "" if err == "invalid_token" else "RFC 6750 section 3.1 error code helps clients refresh")

    qtoken = token or bad_token
    r = call(target=with_query(url, {"access_token": qtoken}))
    if r.ok:
        res.add("query-token-rejected", TOKENS, "critical", FAIL,
                "Token in the URL query string was accepted",
                "access tokens MUST NOT be accepted from the query string; URLs end up in logs and "
                "referrers" + ("" if token else " (accepted even an invalid token)"))
    else:
        res.add("query-token-rejected", TOKENS, "critical", PASS,
                "Token in the URL query string was not accepted", _status_word(r))

    for label, header in (("Basic credentials", "Basic bWNwOnByb2Jl"), ("an empty Bearer", "Bearer")):
        r = call({"Authorization": header})
        cid = "malformed-auth-basic" if label.startswith("Basic") else "malformed-auth-empty"
        if r.ok:
            res.add(cid, TOKENS, "critical", FAIL, "Request with %s was accepted" % label, _status_word(r))
        elif r.status >= 500:
            res.add(cid, TOKENS, "high", FAIL, "Request with %s crashed the server" % label,
                    "%s; expected 400 or 401" % _status_word(r))
        else:
            res.add(cid, TOKENS, "high", PASS, "Request with %s was rejected" % label, _status_word(r))

    if token:
        r = call({"Authorization": "Bearer " + token})
        res.add("valid-token-accepted", TOKENS, "medium", PASS if r.ok else FAIL,
                "Valid token accepted" if r.ok else "The --token you supplied was rejected",
                _status_word(r) + ("" if r.ok else ". Check the token and its audience; "
                                   "the positive-path checks could not run."))
    else:
        res.add("valid-token-accepted", TOKENS, "medium", SKIP,
                "Valid-token check skipped", "pass --token to verify the positive path")

    if foreign_token:
        r = call({"Authorization": "Bearer " + foreign_token})
        if r.ok:
            res.add("audience-validated", TOKENS, "critical", FAIL,
                    "Token issued for another resource was accepted",
                    "the server does not validate the token audience (RFC 8707). This is the "
                    "confused-deputy and token-passthrough risk the MCP spec forbids.")
        else:
            res.add("audience-validated", TOKENS, "critical", PASS,
                    "Token issued for another resource was rejected", _status_word(r))
    else:
        res.add("audience-validated", TOKENS, "critical", SKIP, "Audience check skipped",
                "pass --foreign-token (a valid token issued for a different resource)")

    # ---- transport: origin and CORS
    r = call({"Origin": EVIL_ORIGIN, **({"Authorization": "Bearer " + token} if token else {})})
    acao = r.header("Access-Control-Allow-Origin")
    acac = (r.header("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao and (acao.strip() == EVIL_ORIGIN or (acao.strip() == "*" and acac)):
        res.add("cors-origin", TRANSPORT, "high", FAIL, "CORS trusts an arbitrary origin",
                "Access-Control-Allow-Origin=%s%s for Origin %s" % (
                    acao, " with credentials" if acac else "", EVIL_ORIGIN))
    else:
        res.add("cors-origin", TRANSPORT, "high", PASS, "CORS does not trust an arbitrary origin")
    if token:
        if r.ok:
            res.add("origin-validated", TRANSPORT, "medium", FAIL,
                    "Request from a foreign Origin was served",
                    "Streamable HTTP servers must validate Origin (DNS-rebinding defence) and answer 403")
        else:
            res.add("origin-validated", TRANSPORT, "medium", PASS,
                    "Request from a foreign Origin was refused", _status_word(r))
    else:
        res.add("origin-validated", TRANSPORT, "medium", SKIP, "Origin check skipped",
                "needs --token, otherwise the 401 hides whether Origin is checked")

    # ---- transport: error leakage across every exchange so far
    leaks = []
    for x in client.log:
        if not x.ok and any(p.search(x.body or "") for p in _TRACE_PATTERNS):
            safe_url = re.sub(r"(access_token=)[^&]*", r"\1[redacted]", x.url)
            leaks.append("%s %s -> %d" % (x.method, safe_url, x.status))
    res.add("error-leakage", TRANSPORT, "medium", FAIL if leaks else PASS,
            "Error responses expose stack traces" if leaks else "Error responses expose no stack traces",
            "; ".join(leaks[:3]))

    res.exchanges = len(client.log)
    return res


def _expect_rejected(res: ProbeResult, cid: str, r: Response, what: str) -> None:
    if r.status == 401:
        res.add(cid, TOKENS, "critical", PASS, "Request with %s rejected with 401" % what)
    elif r.ok:
        res.add(cid, TOKENS, "critical", FAIL, "Request with %s was accepted" % what,
                "the server is not validating bearer tokens")
    elif r.status >= 500:
        res.add(cid, TOKENS, "high", FAIL, "Request with %s crashed the server" % what, _status_word(r))
    else:
        res.add(cid, TOKENS, "medium", FAIL, "Request with %s got %s instead of 401" % (what, _status_word(r)),
                "invalid or expired tokens MUST receive 401")


def _check_as(res: ProbeResult, issuer: str, as_url: Optional[str], asm: Optional[dict], tried) -> None:
    if asm is None:
        res.add("as-metadata-reachable", AS_METADATA, "critical", FAIL,
                "Authorization server metadata not found", "tried: " + "; ".join(tried))
        return
    res.add("as-metadata-reachable", AS_METADATA, "critical", PASS,
            "Authorization server metadata found", as_url or "")

    got = asm.get("issuer")
    if isinstance(got, str) and got.rstrip("/") == issuer.rstrip("/"):
        res.add("as-issuer-match", AS_METADATA, "high", PASS, "Issuer matches the advertised server", got)
    else:
        res.add("as-issuer-match", AS_METADATA, "high", FAIL, "Issuer does not match the advertised server",
                "issuer=%r, expected %r (RFC 8414 section 3.3; clients must reject a mismatch)" % (got, issuer))

    methods = asm.get("code_challenge_methods_supported")
    if not isinstance(methods, list):
        res.add("pkce-s256", AS_METADATA, "critical", FAIL, "No code_challenge_methods_supported",
                "MCP clients MUST refuse to proceed when PKCE support is not advertised")
    elif "S256" in methods:
        res.add("pkce-s256", AS_METADATA, "critical", PASS, "PKCE S256 advertised")
    else:
        res.add("pkce-s256", AS_METADATA, "high", FAIL, "PKCE advertised without S256",
                "methods: %s" % ", ".join(map(str, methods)))
    if isinstance(methods, list):
        res.add("pkce-no-plain", AS_METADATA, "low", FAIL if "plain" in methods else PASS,
                "PKCE 'plain' is offered" if "plain" in methods else "PKCE 'plain' is not offered",
                "plain gives no protection if the challenge leaks" if "plain" in methods else "")

    bad, missing = [], []
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        v = asm.get(key)
        if not v:
            if key != "registration_endpoint":
                missing.append(key)
            continue
        if not (str(v).startswith("https://") or is_local(str(v))):
            bad.append("%s=%s" % (key, v))
    if bad:
        res.add("as-endpoints-https", AS_METADATA, "critical", FAIL,
                "Authorization server endpoints not on HTTPS", "; ".join(bad))
    else:
        res.add("as-endpoints-https", AS_METADATA, "critical", PASS, "Authorization server endpoints use HTTPS")
    if missing:
        res.add("as-endpoints-present", AS_METADATA, "high", FAIL,
                "Required endpoints missing from metadata", ", ".join(missing))
    else:
        res.add("as-endpoints-present", AS_METADATA, "high", PASS, "Authorization and token endpoints present")

    rts = asm.get("response_types_supported")
    ok = isinstance(rts, list) and "code" in rts
    res.add("response-type-code", AS_METADATA, "medium", PASS if ok else FAIL,
            "Authorization code flow supported" if ok else "response_types_supported lacks 'code'",
            "" if ok else "RFC 8414 requires the field; OAuth 2.1 uses the code flow")

    gts = asm.get("grant_types_supported")
    legacy = [g for g in (gts or []) if g in ("implicit", "password")] if isinstance(gts, list) else []
    res.add("no-legacy-grants", AS_METADATA, "medium", FAIL if legacy else PASS,
            ("Legacy grants offered: %s" % ", ".join(legacy)) if legacy else "No implicit or password grant",
            "OAuth 2.1 removes the implicit and password grants" if legacy else "")

    cimd = asm.get("client_id_metadata_document_supported") is True
    dcr = bool(asm.get("registration_endpoint"))
    if cimd:
        res.add("client-registration", AS_METADATA, "low", PASS, "Client ID Metadata Documents supported")
    elif dcr:
        res.add("client-registration", AS_METADATA, "low", PASS,
                "Dynamic client registration available",
                "the current spec prefers Client ID Metadata Documents (SHOULD)")
    else:
        res.add("client-registration", AS_METADATA, "low", FAIL,
                "No way for an unknown client to register",
                "advertise client_id_metadata_document_supported or a registration_endpoint, "
                "or every client needs pre-registration")

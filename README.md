# mcp-auth-probe

**Is your remote MCP server's authorization actually right?**

Most MCP security tooling talks to servers over stdio. Production MCP servers run over HTTP behind OAuth, and that is where the real mistakes live: tokens accepted for the wrong audience, tokens taken from the query string, discovery metadata pointing at the wrong resource, authorization servers that never advertised PKCE. `mcp-auth-probe` points at a live MCP endpoint and checks the whole authorization surface against the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) (revision 2025-11-25) and the standards it builds on.

Part of the AAIF MCP toolchain. Standard library only. Python 3.9+. MIT.

## Quick start

```bash
pip install git+https://github.com/shriramkv/mcp-auth-probe
mcp-auth-probe demo          # well-configured sample server, grade A
mcp-auth-probe demo --weak   # misconfigured sample server, grade F
```

Probe a real server:

```bash
mcp-auth-probe probe https://mcp.example.com/mcp

# with tokens, to unlock the positive-path, audience and Origin checks
export MCP_AUTH_PROBE_TOKEN=...            # valid token for this server
export MCP_AUTH_PROBE_FOREIGN_TOKEN=...    # valid token issued for a different resource
mcp-auth-probe probe https://mcp.example.com/mcp --format markdown --fail-on high
```

Tokens can be passed as flags or environment variables and are never printed.

## What it checks

**Discovery** (30%)

| Check | Fails when | Severity |
|---|---|---|
| `unauthenticated-rejected` | a request without a token succeeds (or gets 403 instead of 401) | high / medium |
| `www-authenticate-bearer` | the 401 has no `WWW-Authenticate: Bearer` challenge | high |
| `resource-metadata-hint` | the challenge does not name `resource_metadata` | low |
| `challenge-scope` | the challenge has no `scope` | low |
| `prm-reachable` | protected resource metadata (RFC 9728) is found neither via the hint nor the well-known URIs, tried in the spec's order | critical |
| `prm-hint-resolves` | the advertised `resource_metadata` URL is broken | medium |
| `prm-resource-match` | the metadata `resource` is not the server's canonical URI | high |
| `prm-authorization-servers` | no authorization server is listed | critical |

**Authorization server metadata** (25%): discovered with the RFC 8414 and OpenID Connect paths in the spec's priority order.

| Check | Fails when | Severity |
|---|---|---|
| `as-metadata-reachable` | no metadata at any candidate URL | critical |
| `as-issuer-match` | `issuer` differs from the advertised server | high |
| `pkce-s256` | `code_challenge_methods_supported` is absent (spec clients must refuse) or lacks S256 | critical / high |
| `pkce-no-plain` | `plain` is offered | low |
| `as-endpoints-https` | an authorization, token or registration endpoint is not HTTPS (localhost exempt) | critical |
| `as-endpoints-present` | authorization or token endpoint missing | high |
| `response-type-code` | `code` is not a supported response type | medium |
| `no-legacy-grants` | `implicit` or `password` grants are offered | medium |
| `client-registration` | neither Client ID Metadata Documents nor dynamic registration is available | low |

**Token handling** (30%)

| Check | Fails when | Severity |
|---|---|---|
| `invalid-token-rejected` | a random bearer token is accepted (or does not get 401) | critical |
| `invalid-token-error` | that 401 lacks `error="invalid_token"` | low |
| `query-token-rejected` | `?access_token=` in the URL is accepted | critical |
| `malformed-auth-basic` / `-empty` | Basic credentials or an empty Bearer are accepted, or crash the server | critical / high |
| `valid-token-accepted` | the `--token` you supplied is rejected | medium |
| `audience-validated` | a token issued for another resource is accepted (RFC 8707; the confused-deputy and token-passthrough risk) | critical |

**Transport** (15%)

| Check | Fails when | Severity |
|---|---|---|
| `server-https` | the endpoint is plain HTTP on a non-local host | critical |
| `cors-origin` | CORS reflects an arbitrary origin, or `*` with credentials | high |
| `origin-validated` | a request carrying a foreign `Origin` is served (DNS-rebinding defence) | medium |
| `error-leakage` | any error response contains a stack trace | medium |

Checks that need a token are **skipped**, not passed, when no token is given, and the report says so.

## Grading

Each dimension starts at 100 and loses 40 / 25 / 15 / 8 per failed check (critical / high / medium / low). The overall score is the weighted mean over dimensions that had at least one check run. Any critical finding caps the grade at D. A = 90+, B = 80+, C = 70+, D = 60+, F below 60.

CI gates: `--min-grade B`, `--fail-on high`. Exit 0 ok, 1 gate failed, 2 usage or network error. Formats: `console`, `json`, `markdown`, `badge`, `badge-endpoint`.

## Is it safe to point at production?

Yes, by design. It sends about a dozen ordinary requests: an `initialize` call with no token, with a random token, with malformed headers, with the token in the query string, and with a foreign `Origin`, plus GETs for public metadata documents. It does not brute-force, fuzz, or run an OAuth flow, and it never retries. Still, only probe servers you own or are allowed to test.

## Limits

- It checks what a server *advertises and enforces at the edge*. It cannot see whether tokens are forwarded upstream (token passthrough) beyond what the audience check reveals.
- `audience-validated` needs you to bring a real token for another resource from the same authorization server. Without it the check is skipped.
- Only the first listed authorization server is inspected.

## Try the samples by hand

```bash
mcp-auth-probe serve weak --port 8765
mcp-auth-probe probe http://127.0.0.1:8765/mcp --token demo-valid-token
```

## Where it fits

| Tool | Layer |
|---|---|
| mcp-server-audit, mcp-surface-diff, mcp-context-budget | static analysis of the tool surface |
| mcp-conformance-kit, mcp-fuzz, mcp-load-lab, mcp-replay | runtime behaviour over stdio |
| mcp-guardrail-gateway | runtime enforcement |
| mcp-client-config-audit | client-side wiring |
| **mcp-auth-probe** | **remote transport and authorization** |

## Development

```bash
python -m unittest discover -s tests -t . -v
```

## License

MIT

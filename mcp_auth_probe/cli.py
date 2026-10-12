"""Command-line interface. Exit codes: 0 ok, 1 a CI gate failed, 2 usage or network error."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from . import report as rpt
from . import samples
from .httpc import Client, ProbeNetworkError
from .probe import FAIL, probe

FORMATS = ("console", "json", "markdown", "badge", "badge-endpoint")


def _render(rep, fmt):
    return {
        "json": rpt.render_json, "markdown": rpt.render_markdown, "badge": rpt.render_badge,
        "badge-endpoint": rpt.render_badge_endpoint,
    }.get(fmt, rpt.render_console)(rep)


def _gate(rep, args) -> int:
    code = 0
    if args.min_grade and not rpt.meets(rep["grade"], args.min_grade):
        print("gate: grade %s is below --min-grade %s" % (rep["grade"], args.min_grade), file=sys.stderr)
        code = 1
    if args.fail_on:
        limit = rpt.SEV_ORDER.index(args.fail_on)
        bad = [c for c in rep["results"] if c["status"] == FAIL and rpt.SEV_ORDER.index(c["severity"]) <= limit]
        if bad:
            print("gate: %d finding(s) at %s or above (--fail-on)" % (len(bad), args.fail_on), file=sys.stderr)
            code = 1
    return code


def _headers(pairs):
    out = {}
    for p in pairs or []:
        if ":" not in p:
            raise ValueError("--header expects 'Name: value', got %r" % p)
        k, v = p.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _env_or(value, env):
    return value if value else (os.environ.get(env) or None)


def cmd_probe(args) -> int:
    client = Client(timeout=args.timeout, insecure=args.insecure, extra_headers=_headers(args.header))
    res = probe(args.url, client,
                token=_env_or(args.token, "MCP_AUTH_PROBE_TOKEN"),
                foreign_token=_env_or(args.foreign_token, "MCP_AUTH_PROBE_FOREIGN_TOKEN"),
                expect_public=args.expect_public)
    rep = rpt.build(res)
    text = _render(rep, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return _gate(rep, args)


def cmd_demo(args) -> int:
    kind = "weak" if args.weak else "secure"
    url, srv = samples.start(kind)
    try:
        print("sample '%s' server at %s\n" % (kind, url))
        ns = argparse.Namespace(url=url, token=samples.VALID_TOKEN, foreign_token=samples.FOREIGN_TOKEN,
                                expect_public=False, timeout=5.0, insecure=False, header=None,
                                format=args.format, output=None, min_grade=None, fail_on=None)
        return cmd_probe(ns)
    finally:
        samples.stop(srv)


def cmd_serve(args) -> int:
    url, srv = samples.start(args.kind, port=args.port)
    print("sample '%s' MCP server at %s  (valid token: %s, foreign token: %s)" % (
        args.kind, url, samples.VALID_TOKEN, samples.FOREIGN_TOKEN))
    print("Ctrl+C to stop")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        samples.stop(srv)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="mcp-auth-probe",
                                description="Check the OAuth authorization setup of a remote MCP server.")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = p.add_subparsers(dest="cmd")

    pr = sub.add_parser("probe", help="probe a remote MCP endpoint")
    pr.add_argument("url", help="MCP endpoint URL, e.g. https://mcp.example.com/mcp")
    pr.add_argument("--token", help="a valid access token for this server (or env MCP_AUTH_PROBE_TOKEN)")
    pr.add_argument("--foreign-token",
                    help="a valid token issued for a DIFFERENT resource, to test audience validation "
                         "(or env MCP_AUTH_PROBE_FOREIGN_TOKEN)")
    pr.add_argument("--expect-public", action="store_true",
                    help="the server is intentionally unauthenticated; do not fail on that")
    pr.add_argument("--header", action="append", metavar="'Name: value'", help="extra header on every request")
    pr.add_argument("--timeout", type=float, default=10.0)
    pr.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (testing only)")
    pr.add_argument("--format", choices=FORMATS, default="console")
    pr.add_argument("--output", "-o")
    pr.add_argument("--min-grade", choices=list("ABCDF"))
    pr.add_argument("--fail-on", choices=rpt.SEV_ORDER, help="fail on any finding at this severity or above")
    pr.set_defaults(func=cmd_probe)

    d = sub.add_parser("demo", help="probe a bundled sample server")
    d.add_argument("--weak", action="store_true", help="use the misconfigured sample")
    d.add_argument("--format", choices=FORMATS, default="console")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("serve", help="run a sample server for manual testing")
    s.add_argument("kind", choices=sorted(samples.HANDLERS))
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(func=cmd_serve)

    v = sub.add_parser("version")
    v.set_defaults(func=lambda a: (print(__version__), 0)[1])
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (ProbeNetworkError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

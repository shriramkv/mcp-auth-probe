import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer

from mcp_auth_probe import samples
from mcp_auth_probe.cli import main
from mcp_auth_probe.httpc import Client, parse_www_authenticate
from mcp_auth_probe.probe import (
    FAIL, PASS, SKIP, as_candidates, canonical, prm_candidates, probe, with_query,
)
from mcp_auth_probe.report import build, render_markdown


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def status(res, cid):
    return {c.id: c.status for c in res.checks}[cid]


class HelperTests(unittest.TestCase):
    def test_parse_www_authenticate(self):
        h = 'Bearer resource_metadata="https://x/.well-known/oauth-protected-resource", ' \
            'scope="a b", error="invalid_token", Basic realm="r, with comma"'
        p = parse_www_authenticate(h)
        self.assertEqual(p["bearer"]["resource_metadata"], "https://x/.well-known/oauth-protected-resource")
        self.assertEqual(p["bearer"]["scope"], "a b")
        self.assertEqual(p["bearer"]["error"], "invalid_token")
        self.assertEqual(p["basic"]["realm"], "r, with comma")

    def test_parse_bare_scheme(self):
        self.assertEqual(parse_www_authenticate("Bearer"), {"bearer": {}})
        self.assertEqual(parse_www_authenticate(None), {})

    def test_canonical(self):
        self.assertEqual(canonical("HTTPS://MCP.Example.com:443/mcp/"), "https://mcp.example.com/mcp")
        self.assertEqual(canonical("https://mcp.example.com#frag"), "https://mcp.example.com")
        self.assertEqual(canonical("https://h:8443"), "https://h:8443")

    def test_prm_candidates_order(self):
        self.assertEqual(prm_candidates("https://e.com/public/mcp"), [
            "https://e.com/.well-known/oauth-protected-resource/public/mcp",
            "https://e.com/.well-known/oauth-protected-resource"])
        self.assertEqual(prm_candidates("https://e.com"), ["https://e.com/.well-known/oauth-protected-resource"])

    def test_as_candidates_order(self):
        self.assertEqual(as_candidates("https://a.com/tenant1"), [
            "https://a.com/.well-known/oauth-authorization-server/tenant1",
            "https://a.com/.well-known/openid-configuration/tenant1",
            "https://a.com/tenant1/.well-known/openid-configuration"])
        self.assertEqual(as_candidates("https://a.com/"), [
            "https://a.com/.well-known/oauth-authorization-server",
            "https://a.com/.well-known/openid-configuration"])

    def test_with_query(self):
        self.assertEqual(with_query("https://e.com/mcp?x=1", {"access_token": "t"}),
                         "https://e.com/mcp?x=1&access_token=t")


class ServerTestCase(unittest.TestCase):
    kind = "secure"

    def setUp(self):
        self.url, self.srv = samples.start(self.kind)

    def tearDown(self):
        samples.stop(self.srv)


class SecureServerTests(ServerTestCase):
    def test_all_pass_with_tokens(self):
        res = probe(self.url, Client(timeout=5), token=samples.VALID_TOKEN, foreign_token=samples.FOREIGN_TOKEN)
        fails = [c.id for c in res.checks if c.status == FAIL]
        self.assertEqual(fails, [])
        rep = build(res)
        self.assertEqual(rep["grade"], "A")
        self.assertEqual(rep["score"], 100.0)
        self.assertEqual(rep["checks"]["skipped"], 0)

    def test_without_tokens_skips_positive_checks(self):
        res = probe(self.url, Client(timeout=5))
        for cid in ("valid-token-accepted", "audience-validated", "origin-validated"):
            self.assertEqual(status(res, cid), SKIP)
        self.assertEqual(build(res)["grade"], "A")

    def test_wrong_token_flagged(self):
        res = probe(self.url, Client(timeout=5), token="not-the-right-one")
        self.assertEqual(status(res, "valid-token-accepted"), FAIL)

    def test_cli_gate_passes(self):
        code, out, _ = run(["probe", self.url, "--token", samples.VALID_TOKEN, "--format", "json",
                            "--min-grade", "A", "--fail-on", "low"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["grade"], "A")


class WeakServerTests(ServerTestCase):
    kind = "weak"

    def setUp(self):
        super().setUp()
        self.res = probe(self.url, Client(timeout=5), token=samples.VALID_TOKEN,
                         foreign_token=samples.FOREIGN_TOKEN)

    def test_expected_failures(self):
        expected = {
            "www-authenticate-bearer", "prm-resource-match", "as-issuer-match", "pkce-s256",
            "pkce-no-plain", "as-endpoints-https", "no-legacy-grants", "client-registration",
            "invalid-token-rejected", "query-token-rejected", "malformed-auth-basic",
            "audience-validated", "cors-origin", "origin-validated", "error-leakage",
        }
        fails = {c.id for c in self.res.checks if c.status == FAIL}
        self.assertTrue(expected <= fails, expected - fails)

    def test_fallback_to_root_prm(self):
        self.assertTrue(self.res.prm_url.endswith("/.well-known/oauth-protected-resource"))
        self.assertEqual(status(self.res, "prm-reachable"), PASS)

    def test_grade_capped_and_f(self):
        rep = build(self.res)
        self.assertEqual(rep["grade"], "F")
        self.assertGreaterEqual(rep["failures_by_severity"]["critical"], 3)

    def test_markdown(self):
        md = render_markdown(build(self.res))
        self.assertIn("## MCP authorization probe: grade F", md)
        self.assertIn("`audience-validated`", md)

    def test_cli_gate_fails(self):
        code, _, err = run(["probe", self.url, "--format", "json", "--fail-on", "critical"])
        self.assertEqual(code, 1)
        self.assertIn("--fail-on", err)

    def test_query_token_flagged_even_without_valid_token(self):
        res = probe(self.url, Client(timeout=5))
        self.assertEqual(status(res, "query-token-rejected"), FAIL)


class _Public(samples._Base):
    def do_POST(self):
        self.read_body()
        self.send(200, {"jsonrpc": "2.0", "id": 1, "result": {}})

    def do_GET(self):
        self.send(404, {})


class _Forbidden(samples._Base):
    def do_POST(self):
        self.read_body()
        self.send(403, {"error": "forbidden"})

    def do_GET(self):
        self.send(404, {})


class EdgeTests(unittest.TestCase):
    def serve(self, handler):
        import threading
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return "http://127.0.0.1:%d/mcp" % srv.server_address[1]

    def test_public_server_fails_without_flag(self):
        res = probe(self.serve(_Public), Client(timeout=5))
        self.assertEqual(status(res, "unauthenticated-rejected"), FAIL)
        self.assertEqual(status(res, "prm-reachable"), FAIL)

    def test_public_server_with_flag(self):
        res = probe(self.serve(_Public), Client(timeout=5), expect_public=True)
        self.assertTrue(res.public)
        self.assertEqual([c.status for c in res.checks if c.id != "server-https"], [SKIP])

    def test_403_instead_of_401(self):
        res = probe(self.serve(_Forbidden), Client(timeout=5))
        c = [c for c in res.checks if c.id == "unauthenticated-rejected"][0]
        self.assertEqual((c.status, c.severity), (FAIL, "medium"))

    def test_remote_http_flagged(self):
        from mcp_auth_probe.probe import is_local
        self.assertTrue(is_local("http://localhost:8000/mcp"))
        self.assertFalse(is_local("http://mcp.example.com/mcp"))

    def test_network_error_exit_2(self):
        code, _, err = run(["probe", "http://127.0.0.1:9/mcp", "--timeout", "2"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_bad_header_arg(self):
        code, _, err = run(["probe", "http://127.0.0.1:9/mcp", "--header", "nocolon"])
        self.assertEqual(code, 2)

    def test_demo_commands(self):
        self.assertEqual(run(["demo"])[0], 0)
        code, out, _ = run(["demo", "--weak", "--format", "badge"])
        self.assertEqual(code, 0)
        self.assertIn("img.shields.io", out)


if __name__ == "__main__":
    unittest.main()

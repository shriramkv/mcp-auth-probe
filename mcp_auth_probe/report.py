"""Grading and rendering."""

from __future__ import annotations

import json
from urllib.parse import quote

from . import __version__
from .probe import DIMENSIONS, FAIL, PASS, SKIP, SPEC_REVISION, ProbeResult

PENALTY = {"critical": 40, "high": 25, "medium": 15, "low": 8}
GRADES = (("A", 90), ("B", 80), ("C", 70), ("D", 60), ("F", 0))
GRADE_ORDER = "ABCDF"
SEV_ORDER = ("critical", "high", "medium", "low")
_COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


def grade_for(score: float) -> str:
    for g, floor in GRADES:
        if score >= floor:
            return g
    return "F"


def meets(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) <= GRADE_ORDER.index(minimum)


def build(res: ProbeResult) -> dict:
    dims = {}
    weighted, weight_total = 0.0, 0.0
    for dim, weight in DIMENSIONS.items():
        checks = [c for c in res.checks if c.dimension == dim and c.status != SKIP]
        if not checks:
            dims[dim] = {"score": None, "weight": weight, "passed": 0, "failed": 0}
            continue
        failed = [c for c in checks if c.status == FAIL]
        score = max(0.0, 100.0 - sum(PENALTY[c.severity] for c in failed))
        dims[dim] = {"score": score, "weight": weight, "passed": len(checks) - len(failed), "failed": len(failed)}
        weighted += score * weight
        weight_total += weight
    overall = weighted / weight_total if weight_total else 0.0
    failed_all = [c for c in res.checks if c.status == FAIL]
    if any(c.severity == "critical" for c in failed_all):
        overall = min(overall, 69.0)
    by_sev = {s: sum(1 for c in failed_all if c.severity == s) for s in SEV_ORDER}
    return {
        "tool": "mcp-auth-probe",
        "version": __version__,
        "spec_revision": SPEC_REVISION,
        "server": res.url,
        "public": res.public,
        "protected_resource_metadata": res.prm_url,
        "authorization_server_metadata": res.as_url,
        "http_exchanges": res.exchanges,
        "score": round(overall, 1),
        "grade": grade_for(overall),
        "dimensions": dims,
        "failures_by_severity": by_sev,
        "checks": {
            "passed": sum(1 for c in res.checks if c.status == PASS),
            "failed": len(failed_all),
            "skipped": sum(1 for c in res.checks if c.status == SKIP),
        },
        "results": [c.to_dict() for c in res.checks],
    }


def render_json(rep: dict) -> str:
    return json.dumps(rep, indent=2)


_ICON = {PASS: "PASS", FAIL: "FAIL", SKIP: "skip"}


def render_console(rep: dict) -> str:
    out = ["mcp-auth-probe %s  (MCP authorization spec %s)" % (rep["version"], rep["spec_revision"]),
           "  server : %s" % rep["server"]]
    if rep["protected_resource_metadata"]:
        out.append("  PRM    : %s" % rep["protected_resource_metadata"])
    if rep["authorization_server_metadata"]:
        out.append("  AS     : %s" % rep["authorization_server_metadata"])
    for dim in DIMENSIONS:
        d = rep["dimensions"][dim]
        score = "n/a" if d["score"] is None else "%.0f" % d["score"]
        out.append("")
        out.append("  %s  [%s]" % (dim, score))
        for c in rep["results"]:
            if c["dimension"] != dim:
                continue
            sev = (" [%s]" % c["severity"]) if c["status"] == FAIL else ""
            out.append("    %s %s%s" % (_ICON[c["status"]], c["title"], sev))
            if c["detail"] and c["status"] != PASS:
                out.append("         %s" % c["detail"])
    ch = rep["checks"]
    out.append("")
    out.append("  checks: %d passed, %d failed, %d skipped   score: %.1f   grade: %s" % (
        ch["passed"], ch["failed"], ch["skipped"], rep["score"], rep["grade"]))
    if rep["public"]:
        out.append("  note: the server answered without authorization")
    return "\n".join(out)


def render_markdown(rep: dict) -> str:
    out = ["## MCP authorization probe: grade %s (%.1f)" % (rep["grade"], rep["score"]), "",
           "Server `%s`, checked against MCP authorization spec %s." % (rep["server"], rep["spec_revision"]), "",
           "| Dimension | Score | Passed | Failed |", "|---|---|---|---|"]
    for dim, d in rep["dimensions"].items():
        out.append("| %s | %s | %d | %d |" % (dim, "n/a" if d["score"] is None else "%.0f" % d["score"],
                                             d["passed"], d["failed"]))
    fails = [c for c in rep["results"] if c["status"] == FAIL]
    if fails:
        out += ["", "### Findings", "", "| Severity | Check | Finding | Detail |", "|---|---|---|---|"]
        for c in sorted(fails, key=lambda c: SEV_ORDER.index(c["severity"])):
            out.append("| %s | `%s` | %s | %s |" % (c["severity"], c["id"], c["title"],
                                                     c["detail"].replace("|", "\\|")))
    skips = [c for c in rep["results"] if c["status"] == SKIP]
    if skips:
        out += ["", "Skipped: " + ", ".join("`%s`" % c["id"] for c in skips)]
    return "\n".join(out)


def render_badge(rep: dict) -> str:
    return "https://img.shields.io/badge/%s-%s-%s" % (
        quote("MCP auth"), quote("%s %.0f" % (rep["grade"], rep["score"])), _COLORS[rep["grade"]])


def render_badge_endpoint(rep: dict) -> str:
    return json.dumps({"schemaVersion": 1, "label": "MCP auth",
                       "message": "%s %.0f" % (rep["grade"], rep["score"]), "color": _COLORS[rep["grade"]]})

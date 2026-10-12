# AGENTS.md

Guidance for AI coding agents working on mcp-auth-probe.

## Project
- Pure Python 3.9+, standard library only. Do not add runtime dependencies.
- Package code lives in `mcp_auth_probe/`, tests in `tests/`.
- Every check cites the spec rule it enforces. Keep `SPEC_REVISION` in `mcp_auth_probe/probe.py` in step with the MCP authorization revision the checks follow.

## Workflow
- Always run `python -m unittest discover -s tests -t .` before committing.
- When adding a check, add a failing case to the weak sample server in `mcp_auth_probe/samples.py` and make sure the secure sample still passes.
- Never run `git push --force`.

## Boundaries
- The probe must stay safe to point at production: only send requests a normal unauthenticated client could send, never brute-force, never retry in loops.
- Never print or log the tokens passed with `--token` or `--foreign-token`.
- Do not modify `LICENSE`.

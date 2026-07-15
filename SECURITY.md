# Security policy

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Report them
through the repository's private security channel when available. Include the
affected version, reproduction steps, expected impact, and sanitized
Diaphora/IDA context needed to reproduce the issue.

The security-analysis tools in this project are heuristic triage tools. Their
output is not a vulnerability finding or proof that a security patch exists.

## Supported versions

Only the latest released version and the default branch are currently
supported.

## Technical security boundaries

- Treat IDBs, binaries, exports, logs, and MCP responses as sensitive analysis
  data.
- Keep `DIAPHORA_OUTPUT_ROOT` dedicated to generated results.
- Review tool arguments before allowing an agent to read or write a new path.
- Do not treat heuristic security output as a vulnerability verdict.
- Sanitize addresses, paths, symbols, and strings before sharing logs publicly.

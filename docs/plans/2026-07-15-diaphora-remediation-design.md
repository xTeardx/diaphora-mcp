# Diaphora MCP Remediation Design

## Goal

Make cross-version analysis address-safe and reproducible without replacing Diaphora's matching engine.

## Design

Diaphora `.diaphora` results are the authoritative old-to-new function mapping. A shared mapping layer will normalize addresses, preserve match metadata, and expose explicit added/removed/unmapped states. Analysis tools will use the mapping before any same-address or name fallback.

The callgraph layer will keep old and new graphs separate and compare translated function identities. Metadata transfer will require a mapped target when a results file is supplied and will use one canonical address representation for hexadecimal and decimal SQLite schemas.

Heuristic security analysis will remain triage-only and return evidence/confidence rather than implying a confirmed vulnerability. Statistics will be computed before output limits are applied.

## Testing

Every behavioral fix starts with a failing regression test. Synthetic SQLite fixtures will cover rebased functions, moved functions, decimal addresses, added/removed functions, metadata mapping, graph mapping, and result limits. IDA-dependent tests remain separate from the unit suite.

## GitHub readiness

Add a reproducible CI workflow, tracked lightweight fixtures, dependency notices, security/contribution guidance, and issue/PR templates. Do not distribute IDA or Diaphora binaries in this repository.

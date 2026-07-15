# GitHub-Ready MCP Documentation Design

## Goal

Present Diaphora MCP as a maintainable, agent-friendly open-source MCP server with an English-first public interface and a Russian supplementary guide.

## Research-informed structure

The repository will follow patterns common in mature MCP servers: a short README quick start, explicit client configuration, grouped tool documentation, examples, contributor guidance, security notes, CI, and repository-level agent instructions. The documentation will describe the actual stdio server and licensed local IDA/Diaphora requirements rather than promise a hosted or containerized deployment.

## Scope

- Rewrite `README.md` in English as the canonical landing page.
- Keep `README.ru.md` as a Russian companion with the same essential workflow and links back to English details.
- Add focused docs for configuration, workflows, limitations, and tool selection.
- Add a minimal MCP configuration example and a reproducible sample workflow.
- Clarify `AGENTS.md` for AI coding agents without duplicating implementation details.
- Add CI for tests, compilation, packaging metadata, and repository hygiene.
- Add GitHub issue and pull-request templates.

## Non-goals

- No Docker image: IDA Pro and Diaphora are local, licensed dependencies.
- No automatic publishing to PyPI or an MCP registry.
- No inclusion of IDB, SQLite, binary, or proprietary Diaphora fixtures.

## Acceptance criteria

1. A new user can identify prerequisites, configure an MCP client, run the recommended headless diff workflow, and understand output paths.
2. An AI coding agent can find repository rules, test commands, sensitive fixture restrictions, and the source of truth for architecture.
3. GUI/headless behavior, matching confidence, unsupported inputs, security boundaries, and known limitations are explicit.
4. CI can validate the public repository without IDA Pro.
5. Documentation links and examples are internally consistent with the current function signatures and tests.

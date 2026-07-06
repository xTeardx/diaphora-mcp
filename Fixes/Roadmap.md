# diaphora-mcp Performance Roadmap
## Objective

Transform diaphora-mcp from a SQLite wrapper into a high-performance reverse engineering backend capable of handling databases with 150k–1M functions while remaining responsive for LLM agents.

---

# Phase 0 — Baseline (DO NOT SKIP)

## Goal

Before optimizing anything, understand where time is actually spent.

### Tasks

- [ ] Add timing to every MCP tool.
- [ ] Measure SQL execution time separately.
- [ ] Measure Python processing time.
- [ ] Measure serialization time.
- [ ] Count SQL queries per request.
- [ ] Count rows returned.
- [ ] Count bytes transferred to the LLM.
- [ ] Add memory usage logging.
- [ ] Add cache hit/miss counters (future-proof).
- [ ] Generate a performance report after every request.

### Deliverables

- performance_logger.py
- benchmark_report.json

---

# Phase 1 — SQL Cleanup

## Goal

Remove unnecessary database work.

### Tasks

- [ ] Find every SELECT *.
- [ ] Replace with explicit columns.
- [ ] Review every JOIN.
- [ ] Remove unnecessary ORDER BY.
- [ ] Add LIMIT to every collection query.
- [ ] Review WHERE clauses.
- [ ] Detect duplicated SQL.
- [ ] Detect repeated lookups.
- [ ] Eliminate N+1 queries.

### Deliverables

- Faster SQL
- Reduced memory usage

---

# Phase 2 — Repository Layer

## Goal

SQLite must never be accessed directly by MCP tools.

### Tasks

- [ ] Create Repository package.
- [ ] Move SQL out of MCP tools.
- [ ] Create FunctionRepository.
- [ ] Create GraphRepository.
- [ ] Create MetadataRepository.
- [ ] Create SimilarityRepository.
- [ ] Create StringRepository.

### Deliverables

```
Tool

↓

Repository

↓

SQLite
```

---

# Phase 3 — Memory Index

## Goal

Fast lookups without SQL.

### Tasks

- [ ] Build ID index.
- [ ] Build Address index.
- [ ] Build Name index.
- [ ] Build Hash index.
- [ ] Build Similarity index.
- [ ] Build Namespace index.

### Deliverables

```
O(1)

instead of

SQL
```

---

# Phase 4 — Function Cache

## Goal

Load every function only once.

### Tasks

- [ ] Implement FunctionCache.
- [ ] Cache metadata.
- [ ] Cache names.
- [ ] Cache addresses.
- [ ] Cache similarity.
- [ ] Cache flags.

### Deliverables

```
cache[id]
```

---

# Phase 5 — Lazy Objects

## Goal

Heavy data should load only when requested.

### Tasks

- [ ] Create Function object.
- [ ] Add load_pseudocode().
- [ ] Add load_cfg().
- [ ] Add load_strings().
- [ ] Add load_graph().
- [ ] Add load_imports().
- [ ] Add load_exports().

### Deliverables

Minimal objects with lazy expansion.

---

# Phase 6 — Batch Queries

## Goal

Replace hundreds of SQL queries with one.

### Tasks

- [ ] Implement batch metadata loading.
- [ ] Implement batch similarity loading.
- [ ] Implement batch pseudocode loading.
- [ ] Replace repeated SELECT with WHERE IN.
- [ ] Add bulk API.

### Deliverables

```
get_functions(ids)
```

instead of

```
get_function(id)
```

---

# Phase 7 — Call Graph Engine

## Goal

Never query SQLite for graph traversal.

### Tasks

- [ ] Build adjacency list.
- [ ] Cache reverse edges.
- [ ] Implement BFS.
- [ ] Implement DFS.
- [ ] Cache traversal results.
- [ ] Detect cycles.

### Deliverables

Graph entirely in memory.

---

# Phase 8 — Search Engine

## Goal

Stop searching through SQLite.

### Tasks

- [ ] Build search index.
- [ ] Fuzzy search.
- [ ] Prefix search.
- [ ] Exact search.
- [ ] Namespace search.
- [ ] Regex search.

### Deliverables

Near-instant search.

---

# Phase 9 — Ranking Engine

## Goal

LLM should never receive raw database dumps.

### Tasks

- [ ] Create ranking module.
- [ ] Score changed functions.
- [ ] Score suspicious functions.
- [ ] Score new functions.
- [ ] Score deleted functions.
- [ ] Score by graph centrality.
- [ ] Score by imports.
- [ ] Score by similarity.

### Deliverables

```
Top N
```

instead of

```
Everything
```

---

# Phase 10 — Materialized Statistics

## Goal

Precompute expensive information.

### Tasks

- [ ] Top changed.
- [ ] Top suspicious.
- [ ] Top deleted.
- [ ] Top new.
- [ ] Most connected.
- [ ] Largest functions.

### Deliverables

Instant statistics.

---

# Phase 11 — Query Planner

## Goal

Optimize complex requests automatically.

### Tasks

- [ ] Estimate filter selectivity.
- [ ] Reorder filters.
- [ ] Merge SQL queries.
- [ ] Merge repository calls.
- [ ] Skip redundant work.

### Deliverables

Automatic optimization.

---

# Phase 12 — Cost Model

## Goal

Prevent expensive operations.

### Tasks

- [ ] Assign cost to every MCP tool.
- [ ] Estimate request cost.
- [ ] Reject pathological workloads.
- [ ] Suggest batching.
- [ ] Warn before expensive requests.

### Deliverables

Predictable performance.

---

# Phase 13 — Streaming

## Goal

Avoid loading everything into memory.

### Tasks

- [ ] Replace fetchall().
- [ ] Implement generators.
- [ ] Implement fetchmany().
- [ ] Stream results to MCP.

### Deliverables

Constant memory usage.

---

# Phase 14 — Async Optimization

## Goal

Parallelize independent work.

### Tasks

- [ ] Parallel metadata loading.
- [ ] Parallel strings loading.
- [ ] Parallel imports loading.
- [ ] Parallel exports loading.
- [ ] Parallel similarity lookup.

### Deliverables

Lower latency.

---

# Phase 15 — Knowledge Graph

## Goal

Replace SQLite as runtime model.

### Tasks

- [ ] Create Function node.
- [ ] Create Import node.
- [ ] Create Export node.
- [ ] Create String node.
- [ ] Create Module node.
- [ ] Build relationships.
- [ ] Cache graph.

### Deliverables

Runtime graph model.

---

# Phase 16 — Smart Analysis

## Goal

Move intelligence into MCP.

### Tasks

- [ ] Detect wrapper functions.
- [ ] Detect dispatcher functions.
- [ ] Detect initialization routines.
- [ ] Detect crypto usage.
- [ ] Detect networking.
- [ ] Detect serialization.
- [ ] Detect allocators.
- [ ] Detect logging.
- [ ] Detect thread entry points.

### Deliverables

Semantic analysis.

---

# Phase 17 — Safety

## Goal

Protect the server.

### Tasks

- [ ] Max SQL rows.
- [ ] Max recursion.
- [ ] Max graph depth.
- [ ] Max pseudocode size.
- [ ] Request timeout.
- [ ] Memory limit.
- [ ] Graceful cancellation.

### Deliverables

Stable server.

---

# Phase 18 — Benchmarks

## Goal

Verify every optimization.

### Tasks

- [ ] Benchmark 10k database.
- [ ] Benchmark 50k database.
- [ ] Benchmark 150k database.
- [ ] Benchmark 500k database.
- [ ] Benchmark 1M synthetic database.

Measure:

- startup
- search
- graph traversal
- similarity lookup
- ranking
- pseudocode loading
- memory usage

### Deliverables

benchmark.md

---

# Phase 19 — LLM Optimization

## Goal

Optimize specifically for AI agents.

### Tasks

- [ ] Compress repetitive data.
- [ ] Remove duplicate fields.
- [ ] Return summaries first.
- [ ] Expand on demand.
- [ ] Chunk large responses.
- [ ] Return ranked candidates.

### Deliverables

Minimal token usage.

---

# Phase 20 — Future Improvements

Optional but recommended.

## Ideas

- [ ] Persistent cache.
- [ ] Vector search.
- [ ] Embedding search.
- [ ] Graph neural ranking.
- [ ] Incremental database loading.
- [ ] Live IDA synchronization.
- [ ] Remote SQLite backend.
- [ ] PostgreSQL backend.
- [ ] DuckDB backend.
- [ ] Distributed graph engine.

---

# Definition of Done

The roadmap is considered complete when the following conditions are met:

- Database opening < 5 seconds (150k functions)
- Function lookup < 5 ms
- Callgraph traversal < 20 ms
- Similarity lookup < 10 ms
- No duplicate SQL queries
- No SELECT *
- No N+1 queries
- Lazy loading everywhere
- Batch loading everywhere possible
- Memory-efficient streaming
- Automatic request optimization
- Stable operation on databases containing 1 million functions
- LLM receives only ranked, relevant, minimal context

---

# Development Rules

Every pull request must satisfy the following:

- Never introduce SELECT *
- Never bypass Repository Layer
- Never duplicate SQL
- Prefer batch operations
- Prefer lazy loading
- Cache before optimizing SQL
- Benchmark before and after changes
- Every optimization must include performance measurements
- Every new feature must scale to 1M functions
- Never optimize based on assumptions—always profile first
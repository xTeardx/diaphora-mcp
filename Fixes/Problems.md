# Technical Improvement Plan
## Project: diaphora-mcp
### Goal
Transform diaphora-mcp into a high-performance MCP server capable of efficiently serving very large Diaphora SQLite databases (150k–1M functions) while remaining responsive for LLM agents.

---

# Design Philosophy

The server should not be optimized for today's databases.

It should be optimized for databases an order of magnitude larger.

If the architecture comfortably handles one million functions, then databases with 150k functions will naturally perform extremely well.

Performance improvements should focus on reducing expensive operations instead of making expensive operations slightly faster.

Primary objectives:

- Minimize SQLite access.
- Minimize data transferred to the LLM.
- Cache expensive computations.
- Batch operations whenever possible.
- Treat SQLite as persistent storage rather than the runtime data model.

---

# Priority 1 — Reduce SQLite Access

## Problem

Every SQLite query has overhead:

- file access
- page loading
- object creation
- Python conversion

Large numbers of small queries quickly become the dominant performance cost.

Example:

Instead of

Function
↓

SELECT

↓

Function

↓

SELECT

↓

Function

↓

SELECT

the server should retrieve multiple objects in a single request whenever possible.

## Solution

Introduce a data access layer between MCP tools and SQLite.

```
LLM
 ↓
MCP Tool
 ↓
Repository Layer
 ↓
SQLite
```

The repository layer should cache objects and prevent duplicate queries.

---

# Priority 2 — Function Cache

Frequently requested functions should never be loaded twice.

Implement a FunctionCache.

Example:

```
cache[id] -> Function
```

If a function has already been loaded, return the cached object instead of querying SQLite.

Cache should contain:

- metadata
- addresses
- names
- similarity
- flags

Heavy objects should remain lazy-loaded.

---

# Priority 3 — LRU Cache

LLMs repeatedly ask about the same objects.

Typical sequence:

Show Function A

↓

Show callgraph

↓

Show strings

↓

Show pseudocode

↓

Compare with another function

Without caching this may execute several identical SQL queries.

Introduce independent LRU caches for:

- Function metadata
- Similarity results
- Callgraph
- String references
- Imports
- Exports

---

# Priority 4 — Lazy Loading

Never load information that was not requested.

Instead of returning

Function

- metadata
- pseudocode
- CFG
- strings
- graph
- imports
- exports

return

Function

- metadata

plus methods

```
load_pseudocode()

load_cfg()

load_strings()

load_graph()
```

Heavy data should only be loaded when necessary.

---

# Priority 5 — Batch Operations

Avoid repeated queries like

```
SELECT WHERE id=1

SELECT WHERE id=2

SELECT WHERE id=3
```

Replace with

```
WHERE id IN (...)
```

or JOINs.

Batch operations dramatically reduce SQLite overhead.

---

# Priority 6 — Memory Index

When opening the database, build lightweight in-memory indexes.

Suggested indexes:

```
name -> id

address -> id

hash -> id

ea -> id
```

Searching memory is significantly faster than repeated SQL lookups.

---

# Priority 7 — Warm-up Phase

Immediately after opening the database, preload lightweight tables.

Examples:

- functions
- similarity
- metadata

Do NOT preload:

- pseudocode
- CFG
- graphs

This provides instant response for common queries without excessive memory consumption.

---

# Priority 8 — Never Use SELECT *

Only request required columns.

Bad:

```
SELECT *
```

Good:

```
SELECT id,name,address
```

Large BLOB columns should never be transferred unless explicitly requested.

---

# Priority 9 — Always Apply LIMIT

Every query returning collections should have an upper limit.

Instead of

Show all changed functions

return

Top 100 changed functions

unless the client explicitly requests everything.

This protects both SQLite and the LLM context window.

---

# Priority 10 — Streaming

Avoid fetchall().

Use iterators or fetchmany().

The LLM processes information incrementally.

The server should do the same.

---

# Priority 11 — In-Memory Call Graph

Construct an adjacency list after opening the database.

Example

```
FunctionID

↓

[callees]
```

Graph traversal becomes pure memory access.

BFS and DFS become dramatically faster.

---

# Priority 12 — CFG Cache

CFG generation is expensive.

Cache generated control-flow graphs.

Repeated analysis of the same function should never rebuild the graph.

---

# Priority 13 — Search Engine

SQLite should not perform every search.

Build an in-memory search index.

Possible technologies:

- RapidFuzz
- Trie
- Whoosh

Searching function names becomes effectively instantaneous.

---

# Priority 14 — Materialized Statistics

Many requests repeat the same expensive calculations.

Examples:

- Top changed functions
- Top deleted functions
- Top suspicious functions
- Top new functions

Compute these once during initialization.

Reuse thereafter.

---

# Priority 15 — Query Pipeline

Avoid multiple database round-trips.

Bad:

```
SQLite

↓

Python

↓

SQLite

↓

Python

↓

SQLite
```

Good:

```
SQLite

↓

Python
```

Retrieve everything required in a single optimized query whenever practical.

---

# Priority 16 — Concurrent Reads

SQLite supports concurrent reads efficiently.

Metadata

Strings

Imports

Exports

can often be loaded simultaneously.

Take advantage of asynchronous execution where beneficial.

---

# Priority 17 — Reduce LLM Context

Never return excessive data.

The MCP server should rank and filter results before sending them to the LLM.

Instead of

150,000 functions

return

Top 20 candidates.

Ranking belongs inside the MCP server.

---

# Priority 18 — Hierarchical Analysis

Avoid flat analysis.

Preferred workflow:

Modules

↓

Namespaces

↓

Interesting clusters

↓

Functions

↓

Detailed analysis

This mirrors how experienced reverse engineers work.

---

# Priority 19 — Cost Model

Every MCP tool should expose an estimated execution cost.

Example

FindFunction

Cost = 1

Callgraph

Cost = 4

Similarity

Cost = 3

Export Pseudocode

Cost = 20

The planner can then decide:

- batch requests
- postpone expensive operations
- refuse pathological workloads

---

# Priority 20 — Query Planner

Introduce an optimizer.

Example request:

Find all changed functions

↓

using WinHTTP

↓

calling CryptoAPI

↓

similarity < 0.4

Instead of filtering sequentially,

estimate selectivity.

Apply the most restrictive filters first.

The planner should minimize intermediate result sets.

---

# Priority 21 — Knowledge Graph

The SQLite database should not be treated as the runtime model.

Instead build an internal object graph.

Example

Function

- metadata
- callers
- callees
- imports
- exports
- strings
- similarity
- namespace
- CFG
- pseudocode

SQLite becomes persistent storage.

The runtime operates on graph objects.

---

# Priority 22 — Performance Instrumentation

Every MCP tool should record:

Execution time

SQL execution time

Rows returned

Objects created

Cache hits

Cache misses

Memory usage

This enables evidence-based optimization instead of guesswork.

---

# Priority 23 — Benchmark Suite

Create reproducible benchmarks.

Suggested datasets:

10k functions

50k functions

150k functions

500k functions

Measure

Database opening

Search latency

Callgraph traversal

Similarity lookup

Batch operations

Memory consumption

---

# Priority 24 — Defensive Limits

Protect the server against accidental expensive requests.

Examples:

Maximum rows returned

Maximum recursion depth

Maximum graph depth

Maximum pseudocode size

Maximum execution time

Large requests should require explicit confirmation.

---

# Priority 25 — Future Architecture

Target architecture

```
LLM

↓

Planner

↓

Ranking Engine

↓

Knowledge Graph

↓

Repository Layer

↓

SQLite
```

Responsibilities

Planner

- optimize requests

Ranking Engine

- reduce search space

Knowledge Graph

- runtime object model

Repository

- caching
- batching
- persistence

SQLite

- storage only

---

# Long-Term Vision

The goal is not simply to expose SQLite through MCP.

The goal is to create an intelligent reverse engineering backend.

SQLite should become merely a persistence layer.

The MCP server should:

- understand relationships
- minimize expensive operations
- proactively rank interesting targets
- optimize requests automatically
- deliver only the information required by the LLM

The final system should remain responsive even when analyzing Diaphora databases containing hundreds of thousands or millions of functions.
# Contributing

## Development setup

```powershell
python -m pip install -e .[dev]
python -m pytest -q
python -m compileall -q .
```

IDA Pro, Diaphora, and binary fixtures are external dependencies. Unit tests
must use small synthetic SQLite databases and must not require proprietary
software or ignored local fixtures.

## Pull requests

- Explain the behavior being changed and add a regression test first.
- Keep Diaphora's result mapping authoritative; do not infer cross-version
  identity from equal addresses alone.
- Run the full test and compile checks.
- Do not commit IDA databases, binaries, exports, logs, secrets, or generated
  artifacts.

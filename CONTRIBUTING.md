# Contributing

## Development setup

```powershell
python -m pip install -e .[dev]
python -m pytest -q
python -m compileall -q .
```

IDA Pro and Diaphora are external runtime dependencies. Unit tests must use
small synthetic SQLite databases and must not require a local IDA session or
ignored binary fixtures.

The public CI environment runs the unit suite without IDA. If a change affects
the real export pipeline, also record the local IDA/Diaphora versions and the
backend used for manual verification.

## Pull requests

- Explain the behavior being changed and add a regression test first.
- Keep Diaphora's result mapping authoritative; do not infer cross-version
  identity from equal addresses alone.
- Run the full test and compile checks.
- Do not commit IDA databases, binaries, exports, logs, secrets, or generated
  artifacts.
- Update the relevant English documentation and keep `README.ru.md` aligned
  for user-visible workflows.
- Include sanitized command output and exact reproduction steps for failures.

## Commit scope

Keep commits focused. Separate code fixes, documentation changes, generated
artifacts, and unrelated formatting. Do not add machine-specific absolute paths
to examples or tests.

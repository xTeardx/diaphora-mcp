## Summary

<!-- What changed and why? -->

## Scope

- [ ] Code
- [ ] Tests
- [ ] Documentation
- [ ] Configuration/CI

## Verification

```text
python -m pytest -q
python -m compileall -q .
git diff --check
```

<!-- Add relevant output and, for IDA-dependent work, the tested backend/version. -->

## Data safety

- [ ] No IDB, binary, SQLite export, diff result, log, secret, or generated artifact is included.
- [ ] Paths and logs are sanitized.

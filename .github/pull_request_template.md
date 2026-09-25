## Summary

Describe the user-visible or scientific behavior change.

## Validation

- [ ] `uv run --locked ruff format --check .`
- [ ] `uv run --locked ruff check .`
- [ ] `uv run --locked ty check src tests`
- [ ] `uv run --locked pytest`
- [ ] `uv run --locked pt-bench registry validate`
- [ ] `uv run --locked pt-bench schemas export --output-dir schemas/v1alpha1 --check`

## Benchmark integrity

- [ ] Change is covered by a GitHub Actions execution path.
- [ ] Check, subject, suite, schema, and adapter versions are updated where applicable.
- [ ] No real account data, credentials, private communications, or unrelated captures are included.
- [ ] Product `fail` and harness `error` semantics remain distinct.
- [ ] Historical result formats remain readable or are deliberately versioned.
- [ ] Documentation and methodology changes are included.

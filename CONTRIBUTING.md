# Contributing

All first-party contributions are licensed under AGPL-3.0-only.

## Local checks

```bash
uv sync --locked --all-extras --all-groups
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked mypy src tests
uv run --locked pytest
uv audit --locked --preview-features audit-command
uv run --locked pt-bench registry validate
uv run --locked pt-bench schemas export --output-dir schemas/v1alpha1 --check
```

## Change requirements

- Version every check, subject, suite, and public schema change.
- Never rewrite a historical result.
- Include measured, static, documented/audit, and human-review evidence types explicitly.
- Do not commit secrets, real account data, raw unrelated captures, or generated run output.
- Update `COMMUNICATION_PRIVACY_LANDSCAPE.md` or architecture decisions when the
  methodology, licensing, or operational model changes.
- Add tests for new adapters, evidence handling, and result semantics.

GitHub Actions is the only canonical execution system. Local runs are useful for
development but must record `execution.mode = "local"`.

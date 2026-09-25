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
uv run --locked pt-bench operations validate
uv run --locked pt-bench schemas export --output-dir schemas/v1alpha1 --check
```

`operations validate` exits `0` when every subject is cleared for canonical runs, `2`
while any subject still needs a provider-terms review or a declared lane is
unprovisioned, and `1` when the policy itself is missing or invalid. Only `1` is a
defect.

## Change requirements

- Version every check, subject, suite, and public schema change.
- Never rewrite a historical result.
- Include measured, static, documented/audit, and human-review evidence types explicitly.
- Do not commit secrets, real account data, raw unrelated captures, or generated run output.
- Update `COMMUNICATION_PRIVACY_LANDSCAPE.md` or architecture decisions when the
  methodology, licensing, or operational model changes.
- Add tests for new adapters, evidence handling, and result semantics.

## Operational policy

`operations/<version>/operations.toml` is the checked-in record of the decisions that
must exist before canonical measurement: the reference network vantage, runner lanes,
account recovery procedures, canary services, evidence retention and redaction, the
publication target, and one provider-terms review per subject.

`pt-bench plan` refuses a GitHub Actions run for any subject whose terms review is not
`approved`. The gate is deliberate and fails closed: the main risk in this project is not
a wrong result but a provider account terminated for automating an interaction its terms
do not permit. Use `--allow-unapproved-subjects` only for a dry run that will not
produce a publishable result.

Setting a review to `approved` is a human decision that requires `reviewed_by`,
a `terms_uri`, and the specific `permitted_actions` being authorized. It is not a
configuration detail a contributor should set to unblock a pipeline.

GitHub Actions is the only canonical execution system. Local runs are useful for
development but must record `execution.mode = "local"`.

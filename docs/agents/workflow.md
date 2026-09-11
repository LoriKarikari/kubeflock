# Workflow

## Validation

- Leave test execution to PR CI unless the user explicitly requests local tests. Format changed Go files with `gofmt` and check the diff for whitespace errors.
- Use [Justfile](../../Justfile) for verification recipes and the [CI workflow](../../.github/workflows/ci.yml) for jobs and tool versions. Check CI before claiming it passed.
- Preserve behavior with focused tests when changing nontrivial logic. Extend the existing tests rather than adding another fixture framework.

## Delivery

- Put follow-up work in new conventional commits. Do not amend or force-push unless the user explicitly requests a history rewrite.
- Require explicit authorization before applying cluster changes or permanently deleting storage. A cleanup request is not deployment approval.

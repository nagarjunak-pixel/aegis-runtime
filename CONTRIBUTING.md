# Contributing to AegisRuntime

## Local Verification Gate

Before opening a pull request, ensure the full formal verification gate passes:

```bash
uv sync --all-extras
make verify
cd ui && npm ci && npm run build
```

All changes must maintain:
- `0` Ruff lint or formatting issues (`uv run ruff check src tests`)
- `0` strict Mypy type errors (`uv run mypy src`)
- `>= 95%` test coverage including Hypothesis conservation property checks
- `100%` containment across the 12-vector adversarial red-team suite (`uv run aegis redteam`)

# Contributing

Open an issue describing the input, expected behavior, and a minimal **synthetic** reproducer before a large change. Never upload private captures, production logs, credentials, or database exports.

```console
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install -r requirements-dev.txt
python -m pip install --no-build-isolation --no-deps -e .
python -m ruff check .
python -m ruff format --check .
python -m coverage run -m unittest discover -s tests -v
python -m coverage report --fail-under=85
python -m build --no-isolation
python examples/demo.py
```

Tests must exercise observable behavior, error handling and the documented workflow. Keep runtime dependencies at zero unless a clear use case justifies a change. MIT covers original project code; retain third-party licenses and copyrights for any future reuse. CI only checks/builds; it never commits or publishes. Maintainers review patches manually before incorporating them.

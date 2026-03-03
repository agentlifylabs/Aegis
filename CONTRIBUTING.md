# Contributing to Aegis

Thank you for your interest in contributing. This document covers development
setup, coding conventions, and the pull request process.

---

## Development Setup

**Requirements:** Go 1.22+, `gcc` (SQLite CGo), Python 3.11+.

```bash
git clone https://github.com/aegis-framework/aegis.git
cd aegis

# Build binaries
make build

# Run all tests
make test

# Run Python SDK tests
make python-install python-test

# Run linters
make lint
```

---

## Repository Layout

```
cmd/           CLI binaries (aegisd, aegisctl)
internal/      Private packages (server, config)
pkg/           Public packages (policy, manifest, taint, replay, …)
conformance/   Conformance suite runner and YAML packs
integration/   End-to-end integration tests
deploy/        Docker Compose, systemd, config templates
docs/          User documentation
policies/      Canonical Rego bundle (reference copy)
python/        Python SDK
```

---

## Coding Conventions

### Go

- Follow standard Go idioms (`gofmt`, `go vet`, `golangci-lint`).
- Table-driven tests with `testify/assert` and `testify/require`.
- No `panic` in library code — return errors.
- All exported symbols must have doc comments.
- Keep package dependencies acyclic — `pkg/` packages must not import `internal/`.

### Rego

- One `decide.rego` file per bundle.
- The `else`-chain order is load-bearing — see [Policy Reference](docs/policy.md) for the required order.
- Every rule change must be accompanied by a new conformance test case.
- Comment all helper rules.

### Python

- Type annotations on all public functions.
- Docstrings on all public classes and methods.
- `ruff` for linting.

---

## Testing Requirements

Every PR must:

1. Pass `make test` (all 18 Go packages, race detector enabled).
2. Pass `make python-test` (14 Python tests).
3. Not reduce conformance pack coverage.
4. Include tests for any new behaviour — unit tests in the relevant package
   **and**, if the change affects runtime policy, a new conformance test case.

Do not delete or weaken existing tests without explicit discussion.

---

## Schema Changes

The event envelope schema (`pkg/schema/events.proto`) and manifest schema
(`pkg/manifest/manifest.go`) are versioned. Breaking changes require:

1. A new schema version string.
2. A migration guide documenting how existing data is handled.
3. Backward-compatible read path until the old version is retired.

---

## Pull Request Process

1. **Fork** the repository and create a branch: `git checkout -b feat/my-feature`.
2. **Write tests first** — define the expected behaviour before the implementation.
3. **Make the tests pass** — `make test && make python-test`.
4. **Run the linter** — `make lint`.
5. **Update documentation** — if the change affects user-visible behaviour, update the relevant file in `docs/`.
6. **Open a PR** with a clear description of what changed and why.

PR titles should follow the conventional commit format:
`feat: add X`, `fix: correct Y`, `docs: update Z`, `test: add cases for W`.

---

## Non-Negotiables

These properties must hold across all changes:

- **Deny-by-default** for effectful actions — never introduce allow-by-default paths.
- **No outbound telemetry** — never set `OTEL_SDK_DISABLED`; Aegis telemetry is always opt-out via the exporter, not via the OTel SDK flag.
- **Every run replayable** — the event log is the source of truth; nothing that affects reproducibility may be removed.
- **`make test` runs without network** — all tests must pass in an air-gapped environment.

---

## Security Issues

Please do not open public GitHub issues for security vulnerabilities. Instead,
email the maintainers directly. We aim to respond within 48 hours.

---

## License

By contributing, you agree that your contributions will be licensed under the
Apache 2.0 License.

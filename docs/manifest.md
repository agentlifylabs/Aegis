# Capability Manifest

An `aegis-manifest.json` file declares exactly what an agent skill is allowed
to do. Aegis enforces this at runtime — any action not declared is denied.

---

## Why Manifests Exist

Without a manifest, an agent can call any tool, reach any network destination,
and run indefinitely. A manifest turns the security model from
**allow-by-default** into **deny-by-default**: you declare the minimum set of
permissions the skill needs, and everything else is blocked.

---

## Schema Version

Every manifest must declare the schema version as its first field:

```json
{
  "schema": "aegis.dev/manifest/v0.1"
}
```

Manifests with an unrecognised schema version are rejected at load time.

---

## Full Field Reference

```json
{
  "schema":    "aegis.dev/manifest/v0.1",
  "name":      "my-research-skill",
  "version":   "1.0.0",
  "publisher": "acme-corp",

  "permissions": {
    "tools":   ["read_file", "mcp.https", "write_file"],
    "net": {
      "domains": ["api.openai.com", "*.wikipedia.org"]
    },
    "fs": {
      "read_roots":  ["/workspace"],
      "write_roots": ["/workspace/output"]
    },
    "exec": {
      "allowed_bins": ["/usr/bin/git", "/usr/bin/python3"]
    },
    "approval_required": ["deploy", "send_email"],
    "budgets": {
      "max_steps":        24,
      "max_tool_calls":   12,
      "max_wall_time_ms": 120000,
      "max_output_bytes": 1048576,
      "timeout_ms":       30000,
      "max_model_calls":  10
    }
  },

  "sandbox": {
    "required": true,
    "image":    "ghcr.io/acme/my-skill@sha256:abc123..."
  },

  "integrity": {
    "files": {
      "skill.py":  "sha256hex...",
      "config.json": "sha256hex..."
    },
    "tree_sha256": "sha256hex...",
    "signature":   "cosign-bundle-reference"
  }
}
```

---

## Field Details

### Top-level fields

| Field | Required | Description |
|---|---|---|
| `schema` | ✅ | Must be `"aegis.dev/manifest/v0.1"` |
| `name` | ✅ | Human-readable skill name |
| `version` | ✅ | SemVer string |
| `publisher` | ✅ | Organisation or individual responsible for the skill |

### `permissions.tools`

A list of tool names the skill is allowed to call. Any tool not in this list
returns `PERMISSION_UNDECLARED`.

```json
"tools": ["read_file", "mcp.https", "write_file"]
```

Tool names are **prefix-matched** for network and exec tools:

- `mcp.https` matches any call to `mcp.https`, `mcp.https.post`, etc.
- `exec` matches `exec`, `exec.shell`, etc.

### `permissions.net.domains`

Allowed outbound network destinations. Any network tool call to a domain not
listed returns `EGRESS_DENY`.

```json
"net": {
  "domains": [
    "api.openai.com",
    "*.wikipedia.org",
    "internal.acme.com"
  ]
}
```

Wildcard syntax: `*.example.com` matches any subdomain of `example.com` but
not `example.com` itself. Use both if you need both:

```json
"domains": ["example.com", "*.example.com"]
```

### `permissions.fs`

Filesystem access roots. These are informational for policy (not yet enforced
by the Rego engine itself) but consumed by sandbox configuration.

```json
"fs": {
  "read_roots":  ["/workspace", "/data"],
  "write_roots": ["/workspace/output"]
}
```

### `permissions.exec.allowed_bins`

Explicit allowlist of executables the skill may run. Any `exec` tool call
specifying a `bin` not in this list returns `EXEC_DENY`.

```json
"exec": {
  "allowed_bins": ["/usr/bin/git", "/usr/bin/python3"]
}
```

If `exec` is listed in `permissions.tools` but `allowed_bins` is empty, all
`exec` calls are denied with `EXEC_DENY`. The tool must be declared **and** the
specific binary must be listed.

### `permissions.approval_required`

Tool names that require explicit human approval before execution. When the
agent proposes a call to one of these tools, the response is
`require_approval` / `APPROVAL_REQUIRED` and execution is paused until a
human approves or denies the pending approval request.

```json
"approval_required": ["deploy", "send_email", "database.write"]
```

### `permissions.budgets`

Resource limits for the session. All fields are optional; defaults are shown:

| Field | Default | Description |
|---|---|---|
| `max_steps` | 24 | Maximum number of steps (model + tool calls combined) |
| `max_tool_calls` | 12 | Maximum number of tool calls |
| `max_wall_time_ms` | 120,000 | Maximum session duration in milliseconds |
| `max_output_bytes` | 1,048,576 | Maximum output size per tool call (constraint) |
| `timeout_ms` | 30,000 | Per-call timeout in milliseconds (constraint) |
| `max_model_calls` | unlimited | Maximum number of model calls |

When any counter exceeds its limit, the next `TOOL_CALL_PROPOSED` returns
`BUDGET_EXCEEDED`.

### `sandbox`

```json
"sandbox": {
  "required": true,
  "image":    "ghcr.io/acme/my-skill@sha256:abc123..."
}
```

- `required` must be `true` when any effectful permission is declared (`exec`,
  `fs.write`, or network access). Aegis enforces this at manifest validation
  time.
- `image` is the container image to use for sandboxed execution (used by
  OpenClaw and compatible runtimes).

### `integrity`

Cryptographic proof that the skill files have not been tampered with.

```json
"integrity": {
  "files": {
    "skill.py":   "sha256hex...",
    "config.json": "sha256hex..."
  },
  "tree_sha256": "sha256hex...",
  "signature":   "cosign-bundle-reference"
}
```

- `files` — map of relative path → SHA-256 hex. Verified by `aegisctl manifest install --dir`.
- `tree_sha256` — aggregate hash of all declared files (SHA-256 of sorted `path:hash\n` lines).
- `signature` — Cosign bundle reference. Required in `trust_mode: prod`.

---

## Manifest Validation Rules

A manifest is **invalid** (and rejected at load time) if:

1. `schema` is not `"aegis.dev/manifest/v0.1"`
2. `name`, `version`, or `publisher` is empty
3. Effectful permissions are declared (`exec`, `fs.write`, network) but `sandbox.required` is `false`

---

## Trust Modes

### `dev` (default)

- Manifest signature is not required
- Publisher is not checked against an allowlist
- Missing `integrity.files` is ignored

### `prod`

- `integrity.signature` must be non-empty
- Publisher must be in the configured allowlist
- All declared `integrity.files` hashes must match

Start aegisd in prod mode:

```bash
./bin/aegisd --manifest aegis-manifest.json --trust-mode prod
```

Or in `aegis.yaml`:

```yaml
manifest:   "/etc/aegis/aegis-manifest.json"
trust_mode: "prod"
```

---

## aegisctl Manifest Commands

### Validate

Check a manifest file for schema and semantic correctness:

```bash
./bin/aegisctl manifest validate aegis-manifest.json
# OK

./bin/aegisctl manifest validate bad-manifest.json --trust-mode prod
# Error: manifest: sandbox.required: must be true when exec permissions are declared
```

### Install

Validate and verify file integrity hashes:

```bash
./bin/aegisctl manifest install aegis-manifest.json --dir /path/to/skill
# Verifying file hashes...
# OK: all 3 files match
```

### Show

Pretty-print a manifest with resolved defaults:

```bash
./bin/aegisctl manifest show aegis-manifest.json
```

---

## Generating Manifests for Legacy Skills

The OpenClaw adapter (`pkg/openclaw`) can generate a best-effort manifest for
existing skills that don't have one:

```bash
# Analyse a skill directory and generate a manifest
# (any CRITICAL finding → manifest generated in read-only audit mode)
./bin/aegisctl manifest generate /path/to/legacy-skill
```

Any skill with a `CRITICAL` pattern finding (credential access, download+exec,
etc.) is automatically restricted to **read-only audit mode**: no `exec`, no
network writes, no filesystem writes, sandbox required.

---

## Example: Minimal Read-Only Skill

```json
{
  "schema":    "aegis.dev/manifest/v0.1",
  "name":      "document-reader",
  "version":   "1.0.0",
  "publisher": "acme-corp",
  "permissions": {
    "tools":   ["read_file"],
    "budgets": {
      "max_steps":      12,
      "max_tool_calls": 6
    }
  },
  "sandbox":   {"required": false},
  "integrity": {}
}
```

## Example: Research Skill with Network Access

```json
{
  "schema":    "aegis.dev/manifest/v0.1",
  "name":      "web-researcher",
  "version":   "2.1.0",
  "publisher": "acme-corp",
  "permissions": {
    "tools":   ["read_file", "mcp.https"],
    "net": {
      "domains": ["api.openai.com", "*.wikipedia.org", "arxiv.org"]
    },
    "budgets": {
      "max_steps":        48,
      "max_tool_calls":   20,
      "max_wall_time_ms": 300000
    }
  },
  "sandbox":   {"required": true},
  "integrity": {}
}
```

## Example: Deployment Skill with Approval Gate

```json
{
  "schema":    "aegis.dev/manifest/v0.1",
  "name":      "k8s-deployer",
  "version":   "1.0.0",
  "publisher": "platform-team",
  "permissions": {
    "tools": ["read_file", "exec", "mcp.https"],
    "net": {
      "domains": ["registry.k8s.io", "internal.platform.example.com"]
    },
    "exec": {
      "allowed_bins": ["/usr/local/bin/kubectl", "/usr/bin/helm"]
    },
    "approval_required": ["exec"],
    "budgets": {
      "max_steps":        10,
      "max_tool_calls":   5,
      "max_wall_time_ms": 600000
    }
  },
  "sandbox": {
    "required": true,
    "image":    "ghcr.io/platform-team/k8s-deployer@sha256:..."
  },
  "integrity": {
    "tree_sha256": "abc123..."
  }
}
```

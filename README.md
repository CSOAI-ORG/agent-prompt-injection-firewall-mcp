# Agent Prompt Injection Firewall MCP

[![PyPI](https://img.shields.io/pypi/v/agent-prompt-injection-firewall-mcp)](https://pypi.org/project/agent-prompt-injection-firewall-mcp/) [![Python](https://img.shields.io/pypi/pyversions/agent-prompt-injection-firewall-mcp)](https://pypi.org/project/agent-prompt-injection-firewall-mcp/) [![MCPize](https://img.shields.io/badge/MCPize-Available-blue)](https://mcpize.com)


**WAF for AI agents — block prompt injection before it reaches the LLM**

Agents that blindly forward user input + retrieved documents to other agents are the #1 production AI vulnerability (OWASP LLM01). This MCP is the pre-flight gate.

By [MEOK AI Labs](https://meok.ai).


## Quick Install

| Client | Install |
|--------|---------|
| **Claude Desktop** | [![Install in Claude](https://img.shields.io/badge/Install-Claude-blue)](https://claude.ai) |
| **Cursor** | [![Install in Cursor](https://img.shields.io/badge/Install-Cursor-black)](https://cursor.com) |
| **VS Code** | [![Install in VS Code](https://img.shields.io/badge/Install-VS_Code-blue)](https://code.visualstudio.com) |
| **Windsurf** | [![Install in Windsurf](https://img.shields.io/badge/Install-Windsurf-purple)](https://codeium.com/windsurf) |
| **Docker** | `docker run -p 8000:8000 agent-prompt-injection-firewall-mcp` |
| **pip** | `pip install agent-prompt-injection-firewall-mcp` |

## Install

```bash
pip install agent-prompt-injection-firewall-mcp
```

## Tools

- `scan_prompt`
- `define_custom_rule`
- `list_rules`
- `scan_log`
- `sign_firewall_attestation`

## Claude Desktop

```json
{
  "mcpServers": {
    "agentpromptinjectionfirewall": { "command": "agent-prompt-injection-firewall-mcp" }
  }
}
```

## Tiers

- **Free** — generous daily limit (100-1,000 depending on operation)
- **Pro £199/mo** — unlimited + signed HMAC attestations with public verify URLs — [subscribe](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836)
- **Enterprise £1,499/mo** — multi-tenant + custom predicate DSL + SIEM webhook push — [subscribe](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Why this exists

The EU AI Act (Aug 2026), DORA (live), ISO 42001, and OWASP LLM01 Top-10 all demand runtime controls for agent systems — not just deployment-time audits. This MCP is that runtime control layer, emitting cryptographically signed evidence your auditor accepts.

## Related MEOK A2A MCPs

- [`agent-policy-enforcement-mcp`](https://pypi.org/project/agent-policy-enforcement-mcp/) — per-pair IAM
- [`agent-handoff-certified-mcp`](https://pypi.org/project/agent-handoff-certified-mcp/) — signed delegation chain
- [`agent-prompt-injection-firewall-mcp`](https://pypi.org/project/agent-prompt-injection-firewall-mcp/) — prompt injection WAF
- [`agent-rate-limiter-mcp`](https://pypi.org/project/agent-rate-limiter-mcp/) — fleet-wide quota
- [`agent-audit-logger-mcp`](https://pypi.org/project/agent-audit-logger-mcp/) — hash-chained signed log
- [`a2a-governance-bridge-mcp`](https://pypi.org/project/a2a-governance-bridge-mcp/) — map A2A to compliance frameworks
- [`meok-attestation-verify`](https://pypi.org/project/meok-attestation-verify/) — independent cert verifier

## License

MIT — MEOK AI Labs, 2026.

<!-- mcp-name: io.github.CSOAI-ORG/agent-prompt-injection-firewall-mcp -->

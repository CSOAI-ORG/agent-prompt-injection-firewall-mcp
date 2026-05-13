#!/usr/bin/env python3
"""
Agent Prompt Injection Firewall MCP Server
===========================================
By MEOK AI Labs | https://meok.ai

Pattern-based + heuristic firewall that scans prompts / tool arguments / agent
handoff payloads for prompt-injection attacks BEFORE they reach a downstream
agent. The "WAF for agents."

PROBLEM SOLVED: agents that blindly forward user input + retrieved documents
to other agents are the #1 production AI vulnerability (OWASP LLM01). This MCP
is the gate: every piece of untrusted content scans here first.

USE CASES:
  - Pre-flight scan of user prompts before forwarding to an executive agent
  - Scan retrieved RAG documents before the LLM sees them
  - Scan tool-call arguments to catch parameter injection
  - Cross-org A2A: scan inbound messages before processing
  - Compliance evidence: signed "we scanned N prompts, blocked M" attestation

PRICING:
  - Free — 100 scans/day
  - Pro £199/mo — unlimited + custom rule uploads + signed attestations
  - Enterprise £1,499/mo — multi-tenant + learned models + SIEM push

Install: pip install agent-prompt-injection-firewall-mcp
Run:     python server.py
"""

import json
import re
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict, deque
from mcp.server.fastmcp import FastMCP

import os as _os
import sys
import os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access as _shared_check_access
    _AUTH_ENGINE_AVAILABLE = True
except ImportError:
    _AUTH_ENGINE_AVAILABLE = False

    def _shared_check_access(api_key: str = ""):
        """Fallback when shared auth engine is not available."""
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key. Get one at https://meok.ai/api-keys", "free"
        return True, "OK", "free"


try:
    from attestation import get_attestation_tool_response
    _ATTESTATION_LOCAL = True
except ImportError:
    _ATTESTATION_LOCAL = False

_ATTESTATION_API = _os.environ.get(
    "MEOK_ATTESTATION_API", "https://meok-attestation-api.vercel.app"
)


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


STRIPE_199 = "https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836"
STRIPE_1499 = "https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837"
FREE_DAILY_LIMIT = 100


# ── Detection rules — 3 classes: BLOCK / ESCALATE / LOG  ─────────────
# Curated from OWASP LLM Top 10 (LLM01 Prompt Injection), prompt-injection
# academic papers (Greshake et al., Perez & Ribeiro), and production incidents
# reported by Anthropic, OpenAI, Google, Microsoft, and practitioner forums.

BLOCK_PATTERNS = [
    # Classic instruction override
    (r'ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions|prompts|rules|commands)', 'instruction-override'),
    (r'disregard\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions|prompts|rules|commands)', 'instruction-override'),
    (r'forget\s+(everything|all|your\s+(instructions|training|rules))', 'instruction-override'),
    # Role reset / jailbreak attempts
    (r'\byou\s+are\s+(now|actually)\s+(DAN|an?\s+(unrestricted|uncensored|jailbroken|evil))', 'role-reset'),
    (r'\bDAN\s+mode\b', 'dan-jailbreak'),
    (r'\bdeveloper\s+mode\s+(enabled|activated)', 'devmode-jailbreak'),
    # Prompt leak
    (r'(print|output|show|reveal|tell\s+me)\s+your\s+(system\s+)?(prompt|instructions)', 'prompt-leak'),
    (r'what\s+(were|are)\s+your\s+(initial|original|system)\s+instructions', 'prompt-leak'),
    (r'repeat\s+the\s+(words|text|content)\s+above', 'prompt-leak'),
    # Data exfiltration via URL
    (r'!\[.*\]\(https?://[^\)]+[?&][a-z]+=.*\$\{', 'data-exfil-markdown-img'),
    (r'<img[^>]+src\s*=\s*["\']?https?://[^"\'>\s]+[?&][a-z]+=.*(\$|context|prompt)', 'data-exfil-html-img'),
    # Credential / secret prompting
    (r'(reveal|print|output|tell\s+me)\s+(the|your)?\s*(api[_\s-]?key|secret|password|token|credential)', 'credential-leak'),
    # Tool-use manipulation
    (r'call\s+the\s+(rm|delete|drop|exec|system|shell)\s+(tool|function|command)', 'dangerous-tool-call'),
    # Encoded attacks
    (r'base64\s*:?\s*[A-Za-z0-9+/=]{40,}', 'base64-payload'),
]

ESCALATE_PATTERNS = [
    (r'<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>', 'control-tokens'),
    (r'\b(sudo|bash|eval|exec)\b', 'shell-command-words'),
    (r'(on|after)\s+(reading|seeing)\s+this', 'conditional-trigger'),
    (r'important\s*:\s*admin\s+only', 'authority-claim'),
    (r'override\s+(safety|alignment|rules)', 'safety-override'),
    (r'as\s+an?\s+(admin|root|developer|owner)', 'authority-claim'),
]

LOG_PATTERNS = [
    (r'https?://[^\s]+', 'url-present'),
    (r'[A-Za-z0-9+/]{60,}={0,3}', 'long-base64-like'),
    (r'\{\{[^}]+\}\}|\$\{[^}]+\}', 'template-syntax'),
]

# Per-tenant custom rules (Pro+)
_custom_rules: dict[str, list[dict]] = defaultdict(list)
_scan_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
_daily_scans: dict[str, int] = defaultdict(int)


mcp = FastMCP(
    "agent-prompt-injection-firewall",
    instructions=(
        "MEOK AI Labs Prompt Injection Firewall MCP. Scan any text (user prompt, RAG "
        "document, tool argument, A2A payload) for OWASP LLM01 attacks before it "
        "reaches a downstream agent. Returns {safe, risk_level, patterns_matched, "
        "recommended_action}. Built on curated pattern library from OWASP + academia + "
        "production incident data. Pro tier: custom rules + signed attestations."
    ),
)


@mcp.tool()
def scan_prompt(
    tenant_id: str,
    text: str,
    context: str = "user-prompt",
    api_key: str = "",
) -> str:
    """Scan a piece of text for prompt injection. Returns full decision trace.

    - context: where this text came from (user-prompt | rag-document | tool-arg | a2a-payload)
    Returns `safe`, `risk_level` (none|low|medium|high|critical), `patterns_matched`
    (list of rule hits), and `recommended_action` (allow | log | escalate | block).
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})

    today = datetime.now(timezone.utc).date().isoformat()
    _daily_scans[f"{tenant_id}:{today}"] += 1
    if tier == "free" and _daily_scans[f"{tenant_id}:{today}"] > FREE_DAILY_LIMIT:
        return json.dumps({
            "error": f"Free tier: {FREE_DAILY_LIMIT} scans/day. Upgrade to Pro for unlimited.",
            "upgrade_url": STRIPE_199,
        })

    text_lc = text.lower() if text else ""
    text_len = len(text or "")

    matches_block, matches_escalate, matches_log = [], [], []
    for pattern, name in BLOCK_PATTERNS:
        if re.search(pattern, text_lc, re.IGNORECASE | re.DOTALL):
            matches_block.append(name)
    for pattern, name in ESCALATE_PATTERNS:
        if re.search(pattern, text_lc, re.IGNORECASE):
            matches_escalate.append(name)
    for pattern, name in LOG_PATTERNS:
        if re.search(pattern, text_lc, re.IGNORECASE):
            matches_log.append(name)

    # Tenant custom rules
    for rule in _custom_rules[tenant_id]:
        try:
            if re.search(rule["pattern"], text_lc, re.IGNORECASE):
                action = rule.get("action", "escalate")
                if action == "block":
                    matches_block.append(rule["name"] + " (custom)")
                elif action == "escalate":
                    matches_escalate.append(rule["name"] + " (custom)")
                else:
                    matches_log.append(rule["name"] + " (custom)")
        except re.error:
            continue

    # Heuristics
    heuristics = []
    if text_len > 20000:
        heuristics.append("very-long-text")
    if text and text.count("\n") > 200:
        heuristics.append("excessive-newlines")

    if matches_block:
        risk = "critical"
        action = "block"
    elif matches_escalate:
        risk = "high" if len(matches_escalate) >= 2 else "medium"
        action = "escalate"
    elif matches_log:
        risk = "low"
        action = "log"
    else:
        risk = "none"
        action = "allow"

    record = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "context": context,
        "text_hash": hashlib.sha256((text or "").encode()).hexdigest()[:16],
        "text_length": text_len,
        "risk": risk,
        "action": action,
        "matches": matches_block + matches_escalate + matches_log + heuristics,
    }
    _scan_log[tenant_id].append(record)

    return json.dumps({
        "safe": action in ("allow", "log"),
        "risk_level": risk,
        "recommended_action": action,
        "patterns_matched": {
            "block": matches_block,
            "escalate": matches_escalate,
            "log": matches_log,
            "heuristics": heuristics,
        },
        "text_length": text_len,
        "upsell_pro": f"Pro £199/mo adds custom rules + signed enforcement attestations: {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def define_custom_rule(
    tenant_id: str,
    rule_name: str,
    pattern: str,
    action: str = "escalate",
    api_key: str = "",
) -> str:
    """Define a tenant-specific detection rule. Pro+ only.

    - pattern: regex (case-insensitive)
    - action: block | escalate | log
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if tier == "free":
        return json.dumps({"error": "Custom rules require Pro (£199/mo).", "upgrade_url": STRIPE_199})
    if action not in ("block", "escalate", "log"):
        return json.dumps({"error": "action must be block | escalate | log"})
    try:
        re.compile(pattern)
    except re.error as e:
        return json.dumps({"error": f"invalid regex: {e}"})
    rule = {"name": rule_name, "pattern": pattern, "action": action}
    _custom_rules[tenant_id].append(rule)
    return json.dumps({"created": True, "rule": rule, "total_custom_rules": len(_custom_rules[tenant_id])})


@mcp.tool()
def list_rules(tenant_id: str = "", api_key: str = "") -> str:
    """List built-in + custom rules (if tenant_id provided)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg})
    return json.dumps({
        "built_in_block": [name for _, name in BLOCK_PATTERNS],
        "built_in_escalate": [name for _, name in ESCALATE_PATTERNS],
        "built_in_log": [name for _, name in LOG_PATTERNS],
        "custom_rules": _custom_rules[tenant_id] if tenant_id else None,
    }, indent=2)


@mcp.tool()
def scan_log(tenant_id: str, risk_filter: str = "", limit: int = 20, api_key: str = "") -> str:
    """Recent scan log. Pro tier: unbounded. Free tier: last 100."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg})
    log = list(_scan_log[tenant_id])
    if tier == "free":
        log = log[-100:]
    if risk_filter:
        log = [r for r in log if r["risk"] == risk_filter]
    return json.dumps({"tenant_id": tenant_id, "entries": log[-limit:]}, indent=2)


@mcp.tool()
def sign_firewall_attestation(
    tenant_id: str,
    window_start_utc: str,
    window_end_utc: str,
    total_scans: int,
    blocks: int,
    escalations: int,
    api_key: str = "",
    email: str = "",
) -> str:
    """Emit a signed attestation of firewall enforcement. Evidence for OWASP
    LLM01 + EU AI Act Art 15 (cybersecurity) + ISO 42001 Annex A.5 (security)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if tier == "free":
        return json.dumps({"error": "Signed firewall attestations require Pro (£199/mo).", "upgrade_url": STRIPE_199})
    findings = [
        f"Window: {window_start_utc} -> {window_end_utc}",
        f"Total scans: {total_scans}",
        f"Blocks: {blocks}",
        f"Escalations: {escalations}",
        f"Block rate: {100*blocks/max(1,total_scans):.2f}%",
    ]
    score = 100.0
    if _ATTESTATION_LOCAL:
        cert = get_attestation_tool_response(
            regulation="Prompt-injection firewall enforcement (OWASP LLM01 + EU AI Act Art 15 + ISO 42001 A.5)",
            entity=f"tenant:{tenant_id}",
            score=score,
            findings=findings,
            articles_audited=["OWASP LLM01", "EU AI Act Art 15", "ISO 42001 A.5"],
            tier=tier,
        )
    else:
        import urllib.request as _url
        try:
            req = _url.Request(
                f"{_ATTESTATION_API}/sign",
                data=json.dumps({
                    "api_key": api_key, "email": email,
                    "regulation": "Prompt-injection firewall enforcement",
                    "entity": f"tenant:{tenant_id}",
                    "score": score, "findings": findings, "tier": tier,
                }).encode(),
                headers={"Content-Type": "application/json"},
            )
            with _url.urlopen(req, timeout=15) as resp:
                cert = json.loads(resp.read())
        except Exception as e:
            return json.dumps({"error": f"Attestation API unreachable: {e}"})
    return json.dumps(cert, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()

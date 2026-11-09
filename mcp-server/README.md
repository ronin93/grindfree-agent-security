# @grindfree/agent-security-mcp

stdio MCP server for **PromptShield**, **CrawlSafe**, and **ToolGuard**.

Paid tool calls settle x402 ($0.002 USDC on Base) using **the caller's** wallet via `X402_PRIVATE_KEY` or `PRIVATE_KEY`. GrindFree keys are never used or accepted.

## Run (npx / local)

```bash
# from this package directory after npm install
X402_PRIVATE_KEY=0xYOUR_BASE_USDC_KEY npx grindfree-agent-security-mcp
# or
node src/index.js
```

Claude Desktop / Cursor MCP config example:

```json
{
  "mcpServers": {
    "grindfree-agent-security": {
      "command": "node",
      "args": ["/absolute/path/to/grindfree-integrations/mcp-server/src/index.js"],
      "env": { "X402_PRIVATE_KEY": "0xYOUR_KEY" }
    }
  }
}
```

## Tools

| Tool | Endpoint | Notes |
|---|---|---|
| `promptshield_screen` | POST https://promptshield.grindfree.net/v1/screen | risk + findings + sanitized |
| `promptshield_clean` | POST https://promptshield.grindfree.net/v1/clean | HTML → LLM text |
| `crawlsafe_check` | POST https://crawlsafe.grindfree.net/v1/check | robots / X-Robots-Tag; not malware |
| `toolguard_evaluate` | POST https://toolguard.grindfree.net/v1/evaluate | allow\|review\|deny; **caller must enforce**. Funded settlement+delivery not independently verified by GrindFree |
| `grindfree_discovery` | (local unpaid probes) | well-known / 402 challenge summary |

## Honesty

- ToolGuard: unpaid 402 + facilitator verify path confirmed; **funded settlement + response delivery not independently verified by GrindFree**.
- Missing owner policy on ToolGuard → `review`.

# @grindfree/agent-security-mcp

stdio MCP server for **PromptShield**, **CrawlSafe**, **ToolGuard**, **CommandGuard**, **MemoryGuard**, **WireShield**, **DocShield**, **SafeRead** and **AskHuman**.

Paid tool calls settle x402 (USDC on Base, $0.001–$0.004 per call) using **the caller's** wallet via `X402_PRIVATE_KEY` or `PRIVATE_KEY`. GrindFree keys are never used or accepted.

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
| `promptshield_screen` | POST https://promptshield.grindfree.net/v1/screen | risk + findings + sanitized · $0.002 |
| `promptshield_clean` | POST https://promptshield.grindfree.net/v1/clean | HTML → LLM text |
| `crawlsafe_check` | POST https://crawlsafe.grindfree.net/v1/check | robots / X-Robots-Tag; not malware |
| `toolguard_evaluate` | POST https://toolguard.grindfree.net/v1/evaluate | allow\|review\|deny; **caller must enforce** · $0.002 |
| `commandguard_command` | POST https://commandguard.grindfree.net/v1/command | shell command check before execution · $0.001 |
| `commandguard_sql` | POST https://commandguard.grindfree.net/v1/sql | SQL check before execution (read_only, protected tables) · $0.001 |
| `memoryguard_screen` | POST https://memoryguard.grindfree.net/v1/screen | screen before writing to agent memory · $0.002 |
| `wireshield_scan` | POST https://wireshield.grindfree.net/v1/scan | outbound leak check on agent output · $0.002 |
| `docshield_scan` | POST https://docshield.grindfree.net/v1/scan | hidden instructions in PDF/Office/HTML/MD; `path` reads a local file · $0.004 |
| `saferead_read` | POST https://saferead.grindfree.net/v1/read | fetch a URL as clean Markdown with hidden text + prompt injections removed/flagged; SSRF-guarded · $0.003 |
| `askhuman_request` | POST https://askhuman.grindfree.net/v1/request | ask the human owner to approve/deny/edit one action (ntfy, Slack, Discord, webhook or link) · $0.03 |
| `askhuman_status` | GET https://askhuman.grindfree.net/status/{id} | decision for a request; long-poll with wait · free |
| `grindfree_discovery` | (local unpaid probes) | well-known / 402 challenge summary |

## Honesty

- Funded settlement + HTTP 200 delivery confirmed by GrindFree self-funded Base USDC tests on every endpoint (not customer usage).
- Decisions are advisory: your agent/adapter must enforce block/deny.
- Missing owner policy on ToolGuard → `review`.

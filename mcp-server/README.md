# @grindfree/agent-security-mcp

stdio MCP server for **PromptShield**, **CrawlSafe**, **ToolGuard**, **CommandGuard**, **MemoryGuard**, **WireShield**, **DocShield**, **SafeRead**, **DocRead**, **AskHuman**, **TrifectaGate** and **ShipCheck** (21 tools).

**Version 0.8.0** — on npm (`@grindfree/agent-security-mcp`) and the MCP Registry (`io.github.ronin93/grindfree-agent-security`).

Paid tool calls settle x402 (USDC on Base, $0.001–$0.03 per call) using **the caller's** wallet via `X402_PRIVATE_KEY` or `PRIVATE_KEY`. GrindFree keys are never used or accepted.

## Run (npx / local)

```bash
X402_PRIVATE_KEY=0xYOUR_BASE_USDC_KEY npx -y @grindfree/agent-security-mcp
# or, from this package directory after npm install
X402_PRIVATE_KEY=0xYOUR_BASE_USDC_KEY npx grindfree-agent-security-mcp
# or
node src/index.js
```

Claude Desktop / Cursor MCP config example:

```json
{
  "mcpServers": {
    "grindfree-agent-security": {
      "command": "npx",
      "args": ["-y", "@grindfree/agent-security-mcp"],
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
| `crawlsafe_check` | POST https://crawlsafe.grindfree.net/v1/check | robots / X-Robots-Tag; not malware · $0.001 |
| `toolguard_evaluate` | POST https://toolguard.grindfree.net/v1/evaluate | allow\|review\|deny; **caller must enforce** · $0.002 |
| `commandguard_command` | POST https://commandguard.grindfree.net/v1/command | shell command check before execution · $0.001 |
| `commandguard_sql` | POST https://commandguard.grindfree.net/v1/sql | SQL check before execution (read_only, protected tables) · $0.001 |
| `memoryguard_screen` | POST https://memoryguard.grindfree.net/v1/screen | screen before writing to agent memory · $0.002 |
| `wireshield_scan` | POST https://wireshield.grindfree.net/v1/scan | outbound leak check on agent output · $0.002 |
| `docshield_scan` | POST https://docshield.grindfree.net/v1/scan | hidden instructions in PDF/Office/HTML/MD; `path` reads a local file · $0.004 |
| `saferead_read` | POST https://saferead.grindfree.net/v1/read | fetch a URL as clean Markdown with hidden text + prompt injections removed/flagged; honours robots.txt; SSRF-guarded · $0.002 (only successful reads charged) |
| `saferead_fetch` | POST https://saferead.grindfree.net/v1/fetch | plain read: URL as clean Markdown, no injection screening (use `saferead_read` for untrusted pages); honours robots.txt · $0.001 |
| `saferead_read_batch` | POST https://saferead.grindfree.net/v1/read-batch | up to 10 URLs as clean Markdown in one call; all-or-nothing (any failure → 424, not charged) · $0.002 per URL |
| `docread_convert` | POST https://docread.grindfree.net/v1/convert | convert PDF to Markdown (also DOCX/XLSX/PPTX/HTML/TXT; url, local path or base64), hidden text + injections removed; `include_findings` adds DocShield's full scan · $0.003 |
| `docread_tables` | POST https://docread.grindfree.net/v1/tables | tables in PDF/DOCX/XLSX/PPTX/HTML → typed JSON (columns, column types, rows); injected cells replaced · $0.004 |
| `askhuman_request` | POST https://askhuman.grindfree.net/v1/request | ask the human owner to approve/deny/edit one action (ntfy, Slack, Discord, webhook or link) · $0.03 |
| `askhuman_status` | GET https://askhuman.grindfree.net/status/{id} | decision for a request; long-poll with wait · free |
| `saferead_watch` | POST https://saferead.grindfree.net/v1/watch | daily change detection: pages read safely, returned as new / changed / unchanged with only added sections; page text never stored · $0.002/URL |
| `shipcheck_scan` | POST https://shipcheck.grindfree.net/v1/check | agent-repo security check for CI: secrets, instruction-file injection, MCP config risks, risky commands, SARIF · $0.01/run |
| `grindfree_quote` | POST https://<service>.grindfree.net/quote | free: exact price and budget fit for planned calls · $0 |
| `trifectagate_check` | POST https://trifectagate.grindfree.net/v1/check | session exfiltration gate before any outbound action: allow/review/block · $0.002 |
| `grindfree_discovery` | (local unpaid probes) | well-known / 402 challenge summary |

## Daily safe digest recipe

Ask your agent (with this MCP) once a day: *"Call saferead_watch with watch_id 'news-digest' on these 10 URLs and summarize only the changes."*
That is $0.02/day ($0.60/month); unchanged pages return no text, new hidden or injected blocks are removed and counted.
A cron / GitHub Actions version without MCP: https://github.com/ronin93/grindfree-agent-security/tree/main/examples/daily-safe-digest

## Budgets

`grindfree_quote` (free) returns the exact USDC cost of planned calls and how many runs a budget buys. Every 402 carries `X-Price-USD`; only HTTP 2xx is charged.

## Honesty

- Funded settlement + HTTP 200 delivery confirmed by GrindFree self-funded Base USDC tests on every endpoint (not customer usage).
- Decisions are advisory: your agent/adapter must enforce block/deny.
- Missing owner policy on ToolGuard → `review`.

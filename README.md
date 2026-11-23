# GrindFree Agent Security

MCP server + client snippets for GrindFree’s pay-per-call agent security APIs on **Base**:

| Service | Endpoint | Price | What it does |
|---|---|---|---|
| **PromptShield** | `POST https://promptshield.grindfree.net/v1/screen` · `/v1/clean` | $0.002 | Prompt-injection screen + HTML→LLM clean text |
| **CrawlSafe** | `POST https://crawlsafe.grindfree.net/v1/check` | $0.001 | robots.txt / X-Robots-Tag crawl gate (SSRF-guarded; **not** malware scanning) |
| **ToolGuard** | `POST https://toolguard.grindfree.net/v1/evaluate` | $0.002 | Pre-tool-call `allow \| review \| deny` policy gate |
| **CommandGuard** | `POST https://commandguard.grindfree.net/v1/command` · `/v1/sql` | $0.001 | Shell command + SQL check before execution: `allow \| warn \| block` |
| **MemoryGuard** | `POST https://memoryguard.grindfree.net/v1/screen` | $0.002 | Screen content before it is written to agent memory (planted instructions, persistence, secrets/PII) |
| **WireShield** | `POST https://wireshield.grindfree.net/v1/scan` | $0.002 | Outbound leak check on agent output (zero-click image exfil, URL smuggling, canaries, prompt leakage) |
| **DocShield** | `POST https://docshield.grindfree.net/v1/scan` | $0.004 | Hidden instructions in PDF / DOCX / XLSX / PPTX / HTML / Markdown before the agent reads them |
| **SafeRead** | `POST https://saferead.grindfree.net/v1/read` | $0.002 | Fetch a URL as clean Markdown with hidden text and prompt injections removed or flagged (SSRF-guarded; HTML, text, JSON, PDF). [Benchmark](benchmarks/hidden-injection/) |
| SafeRead plain | `POST https://saferead.grindfree.net/v1/fetch` | $0.001 | Plain read: URL as clean Markdown, no injection screening |
| SafeRead Watch | `POST https://saferead.grindfree.net/v1/watch` | $0.002 / URL | Daily change detection: each page read safely and returned as new / changed / unchanged with only the added sections. Page text never stored. [Daily safe digest recipe](examples/daily-safe-digest/) |
| **DocRead** | `POST https://docread.grindfree.net/v1/convert` (also `GET ?url=`) | $0.003 | Convert any document (PDF, DOCX, XLSX, PPTX, HTML, text; URL or upload) to clean Markdown for AI, with hidden text and prompt injections stripped and a removal report |
| **AskHuman** | `POST https://askhuman.grindfree.net/v1/request` | $0.03 | Human-in-the-loop approval: one-tap approve/deny/edit link (ntfy, Slack, Discord, webhook); decision by poll, long-poll or signed callback; fails closed |
| **ShipCheck** | `POST https://shipcheck.grindfree.net/v1/check` | $0.01 / run | One CI call for an agent repo: secrets, prompt injection in agent instructions, unpinned/poisoned MCP servers, risky commands; SARIF. [GitHub Action](actions/shipcheck/) |
| **TrifectaGate** | `POST https://trifectagate.grindfree.net/v1/check` | $0.002 | Session exfiltration gate: private data + untrusted content + outbound action → allow / review / block (sticky per-session taint, URL smuggling, secrets in payload) |

**Price:** per call in USDC (table above) on **Base** (`eip155:8453`) via [x402](https://x402.org) v2.  
**Wallet:** the **caller’s** Base USDC wallet pays. This repo never ships GrindFree keys.

### Spending a budget on GrindFree

- **Know the price before paying:** every service has a free `/pricing.json` and a free `/quote` (`POST {"calls":[{"path":"/v1/watch","count":30,"body":{"urls":[...]}}],"budget_usd":1}` → exact total, whether it fits, runs affordable). Every 402 carries `X-Price-USD` and `X-Max-Charge-USD`; paid 200s carry `X-Charged-USD`.
- **Price guarantee:** prices will not increase without at least 30 days' notice, published in each service's `/pricing.json` (`price_guarantee: {no_increase_without_notice_days: 30, since: "2026-11-20"}`) and `llms.txt`.
- **Only success is charged:** 4xx/5xx responses are never settled. All prices are fixed per call or per URL, far below the common $1-per-payment client cap.
- **What $1 buys:** 500 safe page reads, 1,000 plain fetches, 500 watched pages, 100 ShipCheck CI runs, 1,000 shell-command checks, 250 document scans, 33 human approvals.
- **Proof:** all 16 previously listed GrindFree routes are graded A by [SettleWatch](https://settlewatch.com) (independent settlement and uptime monitor, Nov 19 2026); SafeRead removed 129/129 hidden injections with 0/23 false positives in the [open benchmark](benchmarks/hidden-injection/) (rules were tuned on that corpus; 65% and 72% on untuned hold-out sets).

### Recipes

- [Daily safe digest](examples/daily-safe-digest/) — watch 10 pages a day for ~$0.60/month; only changes, injections removed.
- [ShipCheck on every PR](actions/shipcheck/) — $0.01 per pull request; annotations + SARIF.

Contact: [rob@grindfree.net](mailto:rob@grindfree.net) · [@grindfreelabs](https://x.com/grindfreelabs)

---

## Install / run the MCP server (stdio)

**MCP 0.9.0 (22 tools)** is on npm and the MCP Registry (`io.github.ronin93/grindfree-agent-security`):

```bash
X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY npx -y @grindfree/agent-security-mcp
```

From source:

```bash
git clone https://github.com/ronin93/grindfree-agent-security.git
cd grindfree-agent-security/mcp-server
npm install
```

Set the **caller’s** funded Base USDC key in the MCP host env (never commit it):

```bash
export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
# PRIVATE_KEY is also accepted
node src/index.js
```

Claude Desktop / Cursor-style config:

```json
{
  "mcpServers": {
    "grindfree-agent-security": {
      "command": "npx",
      "args": ["-y", "@grindfree/agent-security-mcp"],
      "env": {
        "X402_PRIVATE_KEY": "0xYOUR_KEY"
      }
    }
  }
}
```

### MCP tools

- `promptshield_screen` / `promptshield_clean`
- `crawlsafe_check`
- `toolguard_evaluate` — **your agent must enforce** allow/review/deny before executing the tool; this API cannot stop a bypass
- `commandguard_command` / `commandguard_sql` — check shell commands and SQL before running them
- `memoryguard_screen` — check content before saving it to long-term memory
- `wireshield_scan` — check agent output before rendering/sending it
- `docshield_scan` — check a local file (`path`), base64 bytes, or HTML/Markdown for hidden instructions (max 3 MB)
- `saferead_read` — fetch a web page as clean Markdown with hidden text and prompt injections removed (honours robots.txt)
- `saferead_fetch` — plain read: a web page as clean Markdown for $0.001, no injection screening (use `saferead_read` for untrusted pages)
- `saferead_read_batch` — up to 10 web pages as clean Markdown in one call ($0.002 per URL, all-or-nothing)
- `saferead_search` — search the web without prompt injection ($0.02 per search): ranked sources plus the top 3 pages as clean Markdown, per-page injection flag (search results by You.com)
- `saferead_watch` — check pages for changes on a schedule ($0.002 per URL): new / changed / unchanged, only added sections, injections removed
- `shipcheck_scan` — agent-repo security check for CI ($0.01 per run): secrets, instruction-file injection, MCP config risks, risky commands; SARIF
- `grindfree_quote` — free price quote and budget fit for planned calls (no wallet needed)
- `docread_convert` — convert PDF to Markdown (also DOCX/XLSX/PPTX/HTML; `url`, local `path`, base64 or inline content), injections stripped, with a removal report (max 3 MB)
- `docread_tables` — extract tables from PDF/DOCX/XLSX/PPTX/HTML to typed JSON ($0.004)
- `trifectagate_check` / `askhuman_request` / `askhuman_status` — exfiltration gate and human approval
- `grindfree_discovery` — unpaid 402 / discovery probe (no spend)

---

## Docker

A root `Dockerfile` builds the stdio MCP server. The wallet is supplied at runtime, never baked in:

```bash
docker build -t grindfree-agent-security .
docker run --rm -i -e X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY grindfree-agent-security
```

`glama.json` lists `ronin93` as maintainer so the [Glama listing](https://glama.ai/mcp/servers/ronin93/grindfree-agent-security) can be claimed (requires a one-time GitHub sign-in on glama.ai).

## HTTP snippets (no MCP)


- `examples/typescript-x402-fetch.ts` — official `@x402/fetch` + `@x402/evm`
- `examples/python-x402.py` — unpaid probes + paid hook
- `examples/langchain-tool.py` — LangChain-style wrappers

Unpaid challenge (no wallet):

```bash
curl -sS -D - -o /tmp/ps402.json -X POST https://promptshield.grindfree.net/v1/screen \
  -H 'content-type: application/json' \
  -d '{"content":"hi","format":"text"}'
# Expect HTTP 402 + PAYMENT-REQUIRED
```

---

## Honest limits

- Heuristic / policy layers — not a full security program.
- CrawlSafe is **not** malware, phishing, or legal/ToS advice.
- All guards are deterministic rule packs (no LLM), so they are fast and cheap but can miss novel phrasing; decisions are advisory and **your code must enforce block/deny**.
- DocShield parses structure and text; it does not OCR images or render pages, and legacy .doc/.xls/.ppt return 415 (not charged).
- SafeRead does not run JavaScript or OCR images; pages that discuss prompt injection may have example blocks removed (use `mode:"flag"`). Blocked URLs, failed fetches and unsupported types are not charged.
- AskHuman asks; it does not enforce: run the action only when status is `approved` (or `edited`, using `edited_args`). Invalid requests and failed notifications are not charged.
- ToolGuard returns a decision; **the caller/adapter must enforce it** before tool execution. Missing policy → `review`. Not an exfiltration guarantee.
- ToolGuard: always enforce allow|review|deny in your adapter before tool execution (the API cannot stop a bypass). GrindFree has confirmed funded settlement + HTTP 200 delivery on `/v1/evaluate` via a self-funded Base USDC test; still verify with your own wallet in production.

---

## License

MIT — see [LICENSE](./LICENSE).

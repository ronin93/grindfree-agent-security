# GrindFree Agent Security

MCP server + client snippets for GrindFree’s pay-per-call agent security APIs on **Base**:

| Service | Endpoint | Price | What it does |
|---|---|---|---|
| **PromptShield** | `POST https://promptshield.grindfree.net/v1/screen` · `/v1/clean` | $0.002 | Prompt-injection screen + HTML→LLM clean text |
| **CrawlSafe** | `POST https://crawlsafe.grindfree.net/v1/check` | $0.002 | robots.txt / X-Robots-Tag crawl gate (SSRF-guarded; **not** malware scanning) |
| **ToolGuard** | `POST https://toolguard.grindfree.net/v1/evaluate` | $0.002 | Pre-tool-call `allow \| review \| deny` policy gate |
| **CommandGuard** | `POST https://commandguard.grindfree.net/v1/command` · `/v1/sql` | $0.001 | Shell command + SQL check before execution: `allow \| warn \| block` |
| **MemoryGuard** | `POST https://memoryguard.grindfree.net/v1/screen` | $0.002 | Screen content before it is written to agent memory (planted instructions, persistence, secrets/PII) |
| **WireShield** | `POST https://wireshield.grindfree.net/v1/scan` | $0.002 | Outbound leak check on agent output (zero-click image exfil, URL smuggling, canaries, prompt leakage) |
| **DocShield** | `POST https://docshield.grindfree.net/v1/scan` | $0.004 | Hidden instructions in PDF / DOCX / XLSX / PPTX / HTML / Markdown before the agent reads them |
| **SafeRead** | `POST https://saferead.grindfree.net/v1/read` | $0.003 | Fetch a URL as clean Markdown with hidden text and prompt injections removed or flagged (SSRF-guarded; HTML, text, JSON, PDF) |
| **AskHuman** | `POST https://askhuman.grindfree.net/v1/request` | $0.03 | Human-in-the-loop approval: one-tap approve/deny/edit link (ntfy, Slack, Discord, webhook); decision by poll, long-poll or signed callback; fails closed |

**Price:** per call in USDC (table above) on **Base** (`eip155:8453`) via [x402](https://x402.org) v2.  
**Wallet:** the **caller’s** Base USDC wallet pays. This repo never ships GrindFree keys.

Contact: [rob@grindfree.net](mailto:rob@grindfree.net) · [@grindfreelabs](https://x.com/grindfreelabs)

---

## Install / run the MCP server (stdio)

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
      "command": "node",
      "args": ["/absolute/path/to/grindfree-agent-security/mcp-server/src/index.js"],
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

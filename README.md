# GrindFree Agent Security

MCP server + client snippets for GrindFree’s pay-per-call agent security APIs on **Base**:

| Service | Endpoint | What it does |
|---|---|---|
| **PromptShield** | `POST https://promptshield.grindfree.net/v1/screen` · `/v1/clean` | Prompt-injection screen + HTML→LLM clean text |
| **CrawlSafe** | `POST https://crawlsafe.grindfree.net/v1/check` | robots.txt / X-Robots-Tag crawl gate (SSRF-guarded; **not** malware scanning) |
| **ToolGuard** | `POST https://toolguard.grindfree.net/v1/evaluate` | Pre-tool-call `allow \| review \| deny` policy gate |

**Price:** `$0.002 USDC` per call on **Base** (`eip155:8453`) via [x402](https://x402.org) v2.  
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
- `grindfree_discovery` — unpaid 402 / discovery probe (no spend)

---

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
- ToolGuard returns a decision; **the caller/adapter must enforce it** before tool execution. Missing policy → `review`. Not an exfiltration guarantee.
- ToolGuard: always enforce allow|review|deny in your adapter before tool execution. Confirm paid settlement + delivery with your own Base USDC wallet (see docs/distribution notes).

---

## License

MIT — see [LICENSE](./LICENSE).

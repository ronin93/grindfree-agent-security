# Daily safe digest (SafeRead Watch)

Check a list of pages every day and get **only what changed**, with hidden text and prompt
injections already removed — safe to hand to an agent or an LLM summary step.

- Service: `POST https://saferead.grindfree.net/v1/watch` — $0.002 USDC per URL per check, x402 on Base.
- 10 URLs once a day ≈ $0.02/day ≈ $0.60/month. Failed calls (robots disallow, fetch errors) are not charged.
- Each result is `new`, `changed` (only the added sections are returned) or `unchanged`.
- Page text is never stored: Watch keeps section hashes per `watch_id` for 90 days.
- The script asks the free quote endpoint first and refuses to run above `MAX_USD`.

## Run

```bash
npm install
export X402_PRIVATE_KEY=0x...   # your own Base USDC wallet key; GrindFree never supplies keys
WATCH_ID=my-daily-digest node digest.mjs   # writes digest.md and prints it
```

Edit `urls.txt` (one URL per line). Schedule it with `workflow/daily-safe-digest.yml`
(GitHub Actions, daily) or `crontab.txt`.

The first run returns every page as `new` (full cleaned text); later runs return changes only.
Pipe `digest.md` into your summarizer or agent.

Prefer MCP? The `saferead_watch` tool in `@grindfree/agent-security-mcp` does the same call.

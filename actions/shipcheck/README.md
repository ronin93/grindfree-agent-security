# ShipCheck GitHub Action

One paid call per pull request ($0.01 USDC on Base via x402) that checks the files an AI agent
trusts or runs:

- **Secrets** committed anywhere in the scanned files
- **Prompt injection and hidden Unicode** in agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, .cursor/rules, SKILL.md, prompt files)
- **MCP configs**: unpinned `npx`/`uvx` packages, inline secrets, plaintext transport, risky commands, tool-description injection, lethal-trifecta toolsets
- **Risky commands** in workflows, package.json scripts, Dockerfiles and shell scripts (`curl | bash`, destructive commands)

Findings appear as PR annotations and a job summary; optional SARIF for GitHub code scanning.
The job fails on `block` findings (or `review` too with `fail-on: review`).

## Use

1. Make a dedicated Base wallet with a little USDC ($1 = 100 runs). Add its key as the repo secret `X402_PRIVATE_KEY`.
2. Copy [`example/shipcheck.yml`](example/shipcheck.yml) to `.github/workflows/shipcheck.yml`.

Inputs: `fail-on` (block|review), `scope` (changed|all), `sarif-file`, `max-usd` (the action asks the
free quote endpoint first and will not pay above this; default 0.01).

## What is sent and charged

- Only agent-relevant text files plus files changed in the PR (max 200 files, 1 MB) go to
  `https://shipcheck.grindfree.net/v1/check`. Binary, lock and vendored files are skipped.
- ShipCheck does not store your files. Only HTTP 2xx responses are charged; errors are free.
- No files to scan → no call, nothing charged.

Rules are deterministic (no LLM): fast and cheap, but they can miss novel phrasing. Treat a pass
as "no known issue found", not as a guarantee.

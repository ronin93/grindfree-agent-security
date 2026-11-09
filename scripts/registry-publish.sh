#!/usr/bin/env bash
# Run AFTER `mcp-publisher login github` has completed successfully.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PUB="${MCP_PUBLISHER:-mcp-publisher}"
if ! command -v "$PUB" >/dev/null 2>&1; then
  if [[ -x /tmp/mcp-pub/mcp-publisher ]]; then
    PUB=/tmp/mcp-pub/mcp-publisher
  else
    echo "mcp-publisher not found; set MCP_PUBLISHER=..." >&2
    exit 1
  fi
fi
cd "$ROOT"
if [[ ! -f server.json ]]; then
  echo "missing server.json in $ROOT" >&2
  exit 1
fi
"$PUB" validate ./server.json
"$PUB" publish ./server.json
echo "Published. Verifying registry API..."
# Official registry lookup
NAME="io.github.ronin93/grindfree-agent-security"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$NAME''', safe=''))")
URL="https://registry.modelcontextprotocol.io/v0/servers/${ENC}"
echo "GET $URL"
curl -sS -A 'GrindFreeRegistryCheck/1.0' "$URL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in list(d)[:12]}, indent=2)[:2000])"

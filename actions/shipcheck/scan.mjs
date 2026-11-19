// ShipCheck GitHub Action: collect agent-relevant files, quote (free), pay $0.01 via x402, report.
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, appendFileSync, statSync, existsSync } from "node:fs";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const URL_ = "https://shipcheck.grindfree.net/v1/check";
const QUOTE = "https://shipcheck.grindfree.net/quote?path=/v1/check";
const MAX_FILES = 200, MAX_TOTAL = 1_000_000, MAX_FILE = 200_000;
const env = process.env;
const out = (k, v) => env.GITHUB_OUTPUT && appendFileSync(env.GITHUB_OUTPUT, `${k}=${v}\n`);
const summary = (s) => env.GITHUB_STEP_SUMMARY && appendFileSync(env.GITHUB_STEP_SUMMARY, s + "\n");
const sh = (c) => { try { return execSync(c, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); } catch { return []; } };

const AGENT = /(^|\/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|SKILL\.md|copilot-instructions\.md|\.mcp\.json|mcp\.json|claude_desktop_config\.json|package\.json|Dockerfile[^/]*)$|(^|\/)\.(cursor|claude|github|vscode)\/|\.prompt(\.md)?$|\.(sh|bash|ya?ml)$/i;
const TEXT_SKIP = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|woff2?|ttf|eot|mp[34]|mov|lock|min\.js|map)$|(^|\/)(node_modules|dist|vendor|\.git)\//i;

let paths = sh("git ls-files").filter((p) => AGENT.test(p));
if (env.SC_SCOPE !== "all" && env.SC_BASE) {
  sh(`git fetch --no-tags --depth=1 origin ${env.SC_BASE}`);
  const changed = sh(`git diff --name-only --diff-filter=ACMR ${env.SC_BASE} HEAD`);
  paths = [...new Set([...paths, ...changed])];
}
const files = []; let total = 0;
for (const p of paths) {
  if (TEXT_SKIP.test(p) || !existsSync(p)) continue;
  const size = statSync(p).size; if (!size || size > MAX_FILE) continue;
  const content = readFileSync(p, "utf8");
  if (content.includes("\u0000")) continue;
  if (files.length >= MAX_FILES || total + content.length > MAX_TOTAL) { console.log(`::warning::ShipCheck limit reached; skipped ${p} and later files`); break; }
  files.push({ path: p, content }); total += content.length;
}
if (!files.length) { console.log("ShipCheck: no agent-relevant files to scan; nothing charged."); out("decision", "pass"); out("findings", 0); process.exit(0); }

const q = await (await fetch(QUOTE)).json().catch(() => ({}));
const max = Number(env.SC_MAX_USD || "0.01");
if (!(Number(q.total_usd) <= max)) { console.log(`::error::ShipCheck quote $${q.total_usd} is above max-usd ${max}; not paying.`); process.exit(1); }

const pk = env.X402_PRIVATE_KEY || "";
if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) { console.log("::error::x402-private-key must be 0x + 64 hex (a Base wallet with USDC)"); process.exit(1); }
const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(privateKeyToAccount(pk)) }] });
const res = await pay(URL_, { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ files, fail_on: env.SC_FAIL_ON || "block", sarif: Boolean(env.SC_SARIF) }) });
const r = await res.json().catch(() => ({}));
if (!res.ok) { console.log(`::error::ShipCheck HTTP ${res.status} (not charged): ${JSON.stringify(r).slice(0, 500)}`); process.exit(1); }

for (const f of r.findings || []) {
  const lvl = f.severity === "block" ? "error" : "warning";
  console.log(`::${lvl} file=${f.file}${f.line ? `,line=${f.line}` : ""},title=${f.rule}::${f.reason}`);
}
if (env.SC_SARIF && r.sarif) writeFileSync(env.SC_SARIF, JSON.stringify(r.sarif));
summary(`### ShipCheck: ${r.decision === "pass" ? "✅ pass" : "❌ fail"}\n\n${files.length} files scanned · block ${r.counts?.block ?? 0} · review ${r.counts?.review ?? 0} · charged $${res.headers.get("x-charged-usd") || "0.010"} USDC\n`);
for (const f of r.findings || []) summary(`- **${f.severity}** \`${f.rule}\` ${f.file}${f.line ? `:${f.line}` : ""} — ${f.reason}`);
out("decision", r.decision); out("findings", (r.findings || []).length);
process.exit(r.pass ? 0 : 1);

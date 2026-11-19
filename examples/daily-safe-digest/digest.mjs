#!/usr/bin/env node
// Daily safe digest: check a list of pages with SafeRead Watch and print only what changed,
// with hidden text and prompt injections already removed. Pays from YOUR wallet (X402_PRIVATE_KEY).
// Cost: $0.002 per URL per run (10 URLs daily ≈ $0.60/month). Failed calls are not charged.
import { readFile, writeFile } from "node:fs/promises";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const WATCH = "https://saferead.grindfree.net/v1/watch";
const QUOTE = "https://saferead.grindfree.net/quote";
const urlsFile = process.env.DIGEST_URLS || "urls.txt";
const watchId = process.env.WATCH_ID || "my-daily-digest";
const maxUsd = Number(process.env.MAX_USD || "0.10"); // refuse to run if a run would cost more
const out = process.env.DIGEST_OUT || "digest.md";

const urls = (await readFile(urlsFile, "utf8")).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
if (!urls.length) throw new Error(`no URLs in ${urlsFile}`);
const chunks = [];
for (let i = 0; i < urls.length; i += 10) chunks.push(urls.slice(i, i + 10));

// Free quote first: know the exact price before paying.
const q = await (await fetch(QUOTE, { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ calls: chunks.map((c) => ({ path: "/v1/watch", body: { urls: c } })), budget_usd: maxUsd }) })).json();
console.error(`quote: $${q.total_usd} for ${urls.length} URLs (budget $${maxUsd}, fits: ${q.budget?.fits})`);
if (q.budget && !q.budget.fits) throw new Error(`run would cost $${q.total_usd}, over MAX_USD=${maxUsd}`);

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk || "")) throw new Error("set X402_PRIVATE_KEY (your Base USDC wallet key)");
const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(privateKeyToAccount(pk)) }] });

const lines = [`# Daily safe digest — ${new Date().toISOString().slice(0, 10)}`, ""];
let spent = 0;
for (const c of chunks) {
  const res = await pay(WATCH, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ urls: c, watch_id: watchId }) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { lines.push(`> ${c.length} URLs failed (HTTP ${res.status}, not charged): ${JSON.stringify(body.errors || body.error || body).slice(0, 300)}`, ""); continue; }
  spent += Number(res.headers.get("x-charged-usd") || 0);
  for (const r of body.results || []) {
    if (r.status === "unchanged") { lines.push(`- ${r.url}: no change`); continue; }
    lines.push("", `## ${r.title || r.url} (${r.status})`, r.url, "");
    if (r.new_injection_attempts) lines.push(`> ${r.new_injection_attempts} new hidden/injected block(s) removed from this page`, "");
    const text = r.status === "new" ? r.content : r.changes;
    lines.push((text || "").slice(0, 4000), "");
  }
}
lines.push("", `_Spent $${spent.toFixed(3)} USDC (SafeRead Watch, $0.002/URL)._`);
await writeFile(out, lines.join("\n"));
console.log(lines.join("\n"));

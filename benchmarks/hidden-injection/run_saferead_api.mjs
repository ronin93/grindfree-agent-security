// Reproduce the SafeRead columns against the LIVE paid API with your own wallet (x402, USDC on Base).
// Cost: 154 pages x ($0.002 /v1/read + $0.001 /v1/fetch) = about $0.46. Set PAYER_PRIVATE_KEY in the environment.
// npm i @x402/fetch @x402/evm viem   then:  node run_saferead_api.mjs
import { readFileSync, writeFileSync } from "fs";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";
const D = new URL(".", import.meta.url).pathname;
const man = JSON.parse(readFileSync(D + "manifest.json", "utf8"));
const account = privateKeyToAccount(process.env.PAYER_PRIVATE_KEY);
const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }] });
const out = { engine: "live-api", mode: "live", at: new Date().toISOString(), read: {}, fetch: {} };
for (const p of man.pages) for (const route of ["read", "fetch"]) {
  const r = await pay(`https://saferead.grindfree.net/v1/${route}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: p.url }) });
  const b = await r.json().catch(() => ({}));
  out[route][p.id] = r.status === 200 ? { content: b.content, verdict: b.verdict ?? null, removed_count: b.removed_count ?? null, flagged_count: b.flagged_count ?? null, bytes: b.source?.bytes } : { error: r.status, body: b };
}
writeFileSync(D + "outputs/saferead.json", JSON.stringify(out));

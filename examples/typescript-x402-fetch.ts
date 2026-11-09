/**
 * Copy-paste TypeScript client using official @x402/fetch.
 * Requires: npm i @x402/fetch @x402/evm viem
 * Env: PRIVATE_KEY = caller's funded Base USDC key (never GrindFree keys)
 */
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
const fetchPaid = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }],
});

export async function promptshieldScreen(content: string, format: "text" | "html" = "text") {
  const res = await fetchPaid("https://promptshield.grindfree.net/v1/screen", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content, format }),
  });
  if (!res.ok) throw new Error(`screen ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function crawlsafeCheck(url: string, user_agent = "MyBot/1.0") {
  const res = await fetchPaid("https://crawlsafe.grindfree.net/v1/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url, user_agent, check_page: true }),
  });
  if (!res.ok) throw new Error(`check ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function toolguardEvaluate(body: Record<string, unknown>) {
  // Honest: funded settlement+delivery for ToolGuard not independently verified by GrindFree.
  const res = await fetchPaid("https://toolguard.grindfree.net/v1/evaluate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`evaluate ${res.status}: ${await res.text()}`);
  return res.json();
}

// Workflow: crawl permission → fetch yourself → screen → branch
const target = "https://promptshield.grindfree.net/";
const gate = await crawlsafeCheck(target);
if (!gate.crawl_allowed) throw new Error("robots disallow");
const html = await (await fetch(target)).text();
const screened = await promptshieldScreen(html, "html");
if (screened.risk === "high") {
  console.log("blocked; safer=", screened.sanitized);
} else {
  console.log("ok", screened.risk, screened.sanitized?.slice?.(0, 120));
}

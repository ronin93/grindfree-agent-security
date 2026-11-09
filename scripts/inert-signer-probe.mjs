#!/usr/bin/env node
/**
 * Official @x402/fetch client against live endpoints with an unfunded
 * throwaway key. Expect: client discovers PAYMENT-REQUIRED, builds a
 * PAYMENT-SIGNATURE, server/facilitator verify path runs, settle fails
 * without moving GrindFree funds (caller key has no USDC).
 * Also runs a zero-R inert signature path matching prior ToolGuard evidence.
 */
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { writeFileSync, mkdirSync } from "fs";

const endpoints = [
  {
    name: "ps-screen",
    url: "https://promptshield.grindfree.net/v1/screen",
    body: { content: "hi", format: "text" },
  },
  {
    name: "ps-clean",
    url: "https://promptshield.grindfree.net/v1/clean",
    body: { content: "<p>hi</p>" },
  },
  {
    name: "cs-check",
    url: "https://crawlsafe.grindfree.net/v1/check",
    body: { url: "https://example.com/" },
  },
  {
    name: "tg-eval",
    url: "https://toolguard.grindfree.net/v1/evaluate",
    body: {
      tool: "http.fetch",
      destination: { host: "grindfree.net", scheme: "https", port: 443, path_class: "homepage" },
      arg_classes: ["url"],
      taint: ["none"],
      secret_labels: ["none"],
      policy: { allow_tools: ["http.fetch"], allow_hosts: ["grindfree.net"], require_https: true },
    },
  },
];

function b64decode(s) {
  return Buffer.from(s, "base64").toString("utf8");
}
function b64encode(s) {
  return Buffer.from(s, "utf8").toString("base64");
}

async function unpaid(ep) {
  const res = await fetch(ep.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(ep.body),
  });
  const pr = res.headers.get("PAYMENT-REQUIRED") || res.headers.get("payment-required");
  const xpr = res.headers.get("X-Payment-Required") || res.headers.get("x-payment-required");
  const json = await res.json().catch(() => ({}));
  return { status: res.status, pr, xpr, json };
}

async function inertZeroR(ep, unpaidRes) {
  // Build a payment payload echoing the challenge but with a zero signature (R=0).
  const offer = unpaidRes.json;
  const payload = {
    x402Version: offer.x402Version || 2,
    scheme: offer.accepts?.[0]?.scheme || "exact",
    network: offer.accepts?.[0]?.network || "eip155:8453",
    payload: {
      signature: "0x" + "00".repeat(65),
      authorization: {
        from: "0x0000000000000000000000000000000000000001",
        to: offer.accepts?.[0]?.payTo,
        value: offer.accepts?.[0]?.amount || "2000",
        validAfter: "0",
        validBefore: String(Math.floor(Date.now() / 1000) + 600),
        nonce: "0x" + "11".repeat(32),
      },
    },
    resource: offer.resource?.url || ep.url,
  };
  const res = await fetch(ep.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "PAYMENT-SIGNATURE": b64encode(JSON.stringify(payload)),
      "X-PAYMENT": b64encode(JSON.stringify(payload)),
    },
    body: JSON.stringify(ep.body),
  });
  const text = await res.text();
  return { status: res.status, bodyHead: text.slice(0, 400), facilitatorHit: /invalid_exact_evm_payload_signature|facilitator|verify|insufficient|settle/i.test(text) };
}

async function clientUnfunded(ep) {
  const pk = generatePrivateKey();
  const account = privateKeyToAccount(pk);
  const paidFetch = wrapFetchWithPaymentFromConfig(fetch, {
    schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }],
  });
  try {
    const res = await paidFetch(ep.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(ep.body),
    });
    const text = await res.text();
    return {
      status: res.status,
      address: account.address,
      bodyHead: text.slice(0, 400),
      reachedVerifyLike: res.status !== 402 || /invalid|insufficient|facilitator|settle|payment/i.test(text),
    };
  } catch (e) {
    return {
      status: "throw",
      address: account.address,
      error: String(e?.message || e).slice(0, 400),
      reachedVerifyLike: /payment|402|facilitator|insufficient|balance|USDC|settle/i.test(String(e)),
    };
  }
}

const out = { at: new Date().toISOString(), results: [] };
for (const ep of endpoints) {
  const u = await unpaid(ep);
  const z = await inertZeroR(ep, u);
  const c = await clientUnfunded(ep);
  const row = {
    name: ep.name,
    url: ep.url,
    unpaid: {
      status: u.status,
      hasPR: Boolean(u.pr),
      hasXPR: Boolean(u.xpr),
      amount: u.json?.accepts?.[0]?.amount,
      bazaar: Boolean(u.json?.extensions?.bazaar),
      // canonical PR must NOT include maxAmountRequired
      prHasMaxAmountRequired: u.pr
        ? JSON.parse(b64decode(u.pr)).accepts?.[0]?.maxAmountRequired != null
        : null,
    },
    inertZeroR: z,
    unfundedClient: c,
  };
  out.results.push(row);
  console.log(
    ep.name,
    "unpaid",
    u.status,
    "zeroR",
    z.status,
    z.bodyHead.slice(0, 80).replace(/\s+/g, " "),
    "client",
    c.status,
    (c.bodyHead || c.error || "").slice(0, 80).replace(/\s+/g, " ")
  );
}

mkdirSync("/workspace/grindfree-integrations/evidence", { recursive: true });
writeFileSync(
  "/workspace/grindfree-integrations/evidence/inert-signer-probe.json",
  JSON.stringify(out, null, 2)
);
console.log("wrote evidence/inert-signer-probe.json");

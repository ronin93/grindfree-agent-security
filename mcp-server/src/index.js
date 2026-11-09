#!/usr/bin/env node
/**
 * GrindFree agent-security MCP (stdio).
 * Exposes PromptShield, CrawlSafe, ToolGuard. Paid calls use the CALLER's
 * wallet via X402_PRIVATE_KEY / PRIVATE_KEY — never GrindFree keys.
 *
 * Unpaid discovery: tools still work for unpaid 402 probes when
 * GRINDFREE_ALLOW_UNPAID=1 (returns the 402 challenge JSON, not product data).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const PS = "https://promptshield.grindfree.net";
const CS = "https://crawlsafe.grindfree.net";
const TG = "https://toolguard.grindfree.net";

function getPaidFetch() {
  const pk = process.env.X402_PRIVATE_KEY || process.env.PRIVATE_KEY;
  if (!pk) return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) {
    throw new Error("X402_PRIVATE_KEY/PRIVATE_KEY must be 0x + 64 hex chars (caller wallet only).");
  }
  const account = privateKeyToAccount(pk);
  return wrapFetchWithPaymentFromConfig(fetch, {
    schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }],
  });
}

async function postJson(url, body, { paid } = { paid: true }) {
  const headers = { "content-type": "application/json", accept: "application/json" };
  const init = { method: "POST", headers, body: JSON.stringify(body) };
  let res;
  if (paid) {
    const paidFetch = getPaidFetch();
    if (!paidFetch) {
      return {
        ok: false,
        status: 0,
        error:
          "Missing X402_PRIVATE_KEY (or PRIVATE_KEY). Set the caller's Base USDC wallet key in the MCP host env. GrindFree never supplies keys.",
      };
    }
    res = await paidFetch(url, init);
  } else {
    res = await fetch(url, init);
  }
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text.slice(0, 2000) };
  }
  return { ok: res.ok, status: res.status, json };
}

const server = new McpServer({
  name: "grindfree-agent-security",
  version: "0.1.0",
});

server.tool(
  "promptshield_screen",
  "Screen untrusted text/HTML for prompt-injection before the model reads it. Paid x402 $0.002 USDC on Base. Returns risk, findings, sanitized. On high risk, prefer sanitized or abort.",
  {
    content: z.string().describe("Untrusted text or HTML to screen"),
    format: z.enum(["text", "html"]).optional().describe("Content format; default text"),
  },
  async ({ content, format }) => {
    const r = await postJson(`${PS}/v1/screen`, { content, format: format || "text" });
    return {
      content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      isError: !r.ok,
    };
  }
);

server.tool(
  "promptshield_clean",
  "Convert HTML to clean LLM-ready text (strips scripts/styles/hidden/zero-width). Paid x402 $0.002 USDC on Base.",
  {
    content: z.string().describe("HTML or text to clean"),
  },
  async ({ content }) => {
    const r = await postJson(`${PS}/v1/clean`, { content });
    return {
      content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      isError: !r.ok,
    };
  }
);

server.tool(
  "crawlsafe_check",
  "Check whether a URL may be crawled for your user-agent (robots.txt + X-Robots-Tag/meta). SSRF-guarded. Not a malware scanner. Paid x402 $0.002 USDC on Base.",
  {
    url: z.string().url().describe("http(s) URL to check"),
    user_agent: z.string().optional().describe("Crawler UA; first token matched against robots groups"),
    check_page: z.boolean().optional().describe("Also fetch up to 64KB for X-Robots-Tag/meta (default true)"),
  },
  async ({ url, user_agent, check_page }) => {
    const body = { url };
    if (user_agent != null) body.user_agent = user_agent;
    if (check_page != null) body.check_page = check_page;
    const r = await postJson(`${CS}/v1/check`, body);
    return {
      content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      isError: !r.ok,
    };
  }
);

server.tool(
  "toolguard_evaluate",
  "Pre-tool-call policy gate for HTTP/MCP outbound actions. Returns allow|review|deny with deterministic reasons. Caller MUST enforce. Not malware scanning or an exfil guarantee. Missing policy → review. Paid x402 $0.002 USDC on Base. Note: funded settlement+delivery not independently verified by GrindFree.",
  {
    tool: z.string().describe("Tool name, e.g. http.fetch or mcp.call"),
    destination: z
      .object({
        host: z.string().optional(),
        scheme: z.string().optional(),
        port: z.number().optional(),
        path_class: z.string().optional(),
      })
      .optional(),
    arg_classes: z.array(z.string()).optional(),
    taint: z.array(z.string()).optional(),
    secret_labels: z.array(z.string()).optional(),
    policy: z.record(z.any()).optional().describe("Owner policy; absent → review"),
    policy_hash: z.string().optional(),
    rule_pack: z.string().optional(),
  },
  async (args) => {
    const r = await postJson(`${TG}/v1/evaluate`, args);
    return {
      content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      isError: !r.ok,
    };
  }
);

server.tool(
  "grindfree_discovery",
  "Return machine-readable discovery URLs and unpaid 402 challenge shapes for PromptShield, CrawlSafe, and ToolGuard (no payment).",
  {},
  async () => {
    const endpoints = [
      { name: "promptshield_screen", url: `${PS}/v1/screen`, body: { content: "hi", format: "text" } },
      { name: "promptshield_clean", url: `${PS}/v1/clean`, body: { content: "<p>hi</p>" } },
      { name: "crawlsafe_check", url: `${CS}/v1/check`, body: { url: "https://example.com/" } },
      {
        name: "toolguard_evaluate",
        url: `${TG}/v1/evaluate`,
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
    const probes = [];
    for (const ep of endpoints) {
      const res = await fetch(ep.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(ep.body),
      });
      const pr = res.headers.get("PAYMENT-REQUIRED") || res.headers.get("payment-required");
      const json = await res.json().catch(() => ({}));
      probes.push({
        name: ep.name,
        url: ep.url,
        status: res.status,
        has_payment_required: Boolean(pr),
        amount: json?.accepts?.[0]?.amount,
        network: json?.accepts?.[0]?.network,
        bazaar: Boolean(json?.extensions?.bazaar),
        resource: json?.resource,
      });
    }
    const text = JSON.stringify(
      {
        origins: { promptshield: PS, crawlsafe: CS, toolguard: TG },
        discovery: {
          well_known: ["/.well-known/x402", "/openapi.json", "/llms.txt"],
          payTo: "0xe4b5827994B7B3Cd38F9830d9ECF58b51B77721b",
          price_usdc: "0.002",
          network: "eip155:8453",
        },
        unpaid_probes: probes,
        payment_note:
          "Paid tools require caller X402_PRIVATE_KEY with Base USDC. ToolGuard funded settlement+delivery not independently verified by GrindFree.",
      },
      null,
      2
    );
    return { content: [{ type: "text", text }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

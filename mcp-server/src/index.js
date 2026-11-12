#!/usr/bin/env node
/**
 * GrindFree agent-security MCP (stdio).
 * Exposes PromptShield, CrawlSafe, ToolGuard, CommandGuard, MemoryGuard,
 * WireShield, DocShield and SafeRead. Paid calls use the CALLER's
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
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";

const PS = "https://promptshield.grindfree.net";
const CS = "https://crawlsafe.grindfree.net";
const TG = "https://toolguard.grindfree.net";
const CG = "https://commandguard.grindfree.net";
const MG = "https://memoryguard.grindfree.net";
const WS = "https://wireshield.grindfree.net";
const DS = "https://docshield.grindfree.net";
const SR = "https://saferead.grindfree.net";
const DOC_MAX_BYTES = 3 * 1024 * 1024;
const policySchema = z.record(z.any()).optional().describe("Optional owner policy, e.g. {mode:'strict', allow_rules:[...]}");
const reply = (r) => ({ content: [{ type: "text", text: JSON.stringify(r, null, 2) }], isError: !r.ok });
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

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
  version: "0.3.0",
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
  "Pre-tool-call policy gate for HTTP/MCP outbound actions. Returns allow|review|deny with deterministic reasons. Caller MUST enforce. Not malware scanning or an exfil guarantee. Missing policy → review. Paid x402 $0.002 USDC on Base. ",
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
  "commandguard_command",
  "Check an agent-generated shell command (bash/sh/zsh/fish/PowerShell/cmd) BEFORE executing it. Returns allow|warn|block with rule codes (rm -rf, curl|sh, force-push to protected branches, credential exfil, cloud/infra deletes, disk wipes). Caller MUST enforce: do not run on block. Paid x402 $0.001 USDC on Base.",
  {
    command: z.string().max(20000).describe("Exact command line the agent intends to run"),
    shell: z.enum(["bash", "sh", "zsh", "fish", "powershell", "cmd"]).optional(),
    policy: policySchema,
  },
  async (a) => reply(await postJson(`${CG}/v1/command`, clean(a)))
);

server.tool(
  "commandguard_sql",
  "Check agent-generated SQL BEFORE executing it: DROP/TRUNCATE, DELETE/UPDATE without WHERE, tautological WHERE, GRANT/role changes, file/command execution, writes in read_only mode, protected tables. Returns allow|warn|block. Caller MUST enforce. Paid x402 $0.001 USDC on Base.",
  {
    sql: z.string().max(50000).describe("One or more SQL statements"),
    dialect: z.enum(["postgres", "mysql", "mariadb", "sqlite", "mssql", "snowflake", "bigquery", "other"]).optional(),
    policy: policySchema.describe("e.g. {read_only:true} or {protected_tables:['users'], allow_write_tables:['events']}"),
  },
  async (a) => reply(await postJson(`${CG}/v1/sql`, clean(a)))
);

server.tool(
  "memoryguard_screen",
  "Screen content BEFORE writing it to an agent's long-term memory: planted instructions, persistence/trigger attacks ('from now on…', 'whenever the user asks…'), exfil setups, secrets and PII. Source-aware (user vs tool/web/email). Returns allow|review|block plus a sanitized copy. Paid x402 $0.002 USDC on Base.",
  {
    content: z.string().max(16000).optional().describe("Single memory entry (or use entries)"),
    source: z.enum(["user", "assistant", "tool", "web", "document", "email", "retrieved", "mcp", "unknown"]).optional(),
    memory_type: z.enum(["fact", "preference", "instruction", "episodic", "summary"]).optional(),
    entries: z.array(z.object({ key: z.string().optional(), content: z.string(), source: z.string().optional() })).max(25).optional(),
    policy: policySchema,
  },
  async (a) => reply(await postJson(`${MG}/v1/screen`, clean(a)))
);

server.tool(
  "wireshield_scan",
  "Scan agent OUTPUT before it is rendered or sent: zero-click markdown-image exfil, data smuggled in URLs/DNS labels, deceptive links, leaked canary tokens, system-prompt leakage, hidden Unicode, active HTML, secrets and PII. Returns allow|review|block plus a sanitized copy. Paid x402 $0.002 USDC on Base.",
  {
    content: z.string().max(100000).describe("Agent output about to be shown or sent"),
    format: z.enum(["markdown", "text", "html", "json"]).optional(),
    allowed_domains: z.array(z.string()).optional().describe("Hosts allowed to auto-load images"),
    canaries: z.array(z.string()).optional().describe("Canary tokens planted in your system prompt"),
    system_prompt: z.string().optional().describe("Optional; used only for verbatim-overlap detection, never stored"),
    policy: policySchema,
  },
  async (a) => reply(await postJson(`${WS}/v1/scan`, clean(a)))
);

server.tool(
  "docshield_scan",
  "Scan a document BEFORE the agent reads it for hidden instructions: PDF (invisible/white/microscopic/off-page text, annotations, metadata, JavaScript), DOCX/XLSX/PPTX (hidden runs/sheets/rows/slides, speaker notes, comments, remote templates, DDE), HTML, Markdown. Returns allow|review|block and optional visible-only safe_text. Max 3 MB. Paid x402 $0.004 USDC on Base (unsupported/unparseable files are not charged).",
  {
    path: z.string().optional().describe("Local file path (read by this MCP server on your machine)"),
    content_base64: z.string().optional().describe("File bytes, base64 (alternative to path)"),
    content: z.string().optional().describe("HTML/Markdown/text (alternative to path)"),
    format: z.enum(["html", "markdown", "text"]).optional(),
    filename: z.string().optional(),
    include_text: z.boolean().optional().describe("Return visible-only safe_text"),
    policy: policySchema,
  },
  async ({ path, ...a }) => {
    const body = clean(a);
    if (path) {
      const st = await stat(path).catch(() => null);
      if (!st || !st.isFile()) return reply({ ok: false, status: 0, error: `File not found: ${path}` });
      if (st.size > DOC_MAX_BYTES) return reply({ ok: false, status: 0, error: `File is ${st.size} bytes; DocShield max is ${DOC_MAX_BYTES}. Not sent, not charged.` });
      body.content_base64 = (await readFile(path)).toString("base64");
      body.filename = body.filename || basename(path);
    }
    if (!body.content_base64 && !body.content) return reply({ ok: false, status: 0, error: "Provide path, content_base64 or content." });
    return reply(await postJson(`${DS}/v1/scan`, body));
  }
);

server.tool(
  "saferead_read",
  "Safe web reader: fetch a URL and get clean Markdown (or text) with hidden content (display:none, font-size:0, off-screen, comments, invisible Unicode) and prompt-injection instructions removed or flagged. Returns title, content, removed/flagged segments with reasons, an allow|warn|block verdict and fetch metadata. SSRF-guarded; HTML, text, JSON, PDF. Use instead of a raw fetch for pages the agent did not write. Paid x402 $0.003 USDC on Base (blocked URLs, failed fetches and unsupported types are not charged).",
  {
    url: z.string().url().describe("http(s) URL to read"),
    format: z.enum(["markdown", "text"]).optional().describe("Output format; default markdown"),
    mode: z.enum(["strip", "flag"]).optional().describe("strip removes injected blocks (default); flag keeps and lists them"),
    max_chars: z.number().int().min(1000).max(200000).optional().describe("Max content characters (default 50000)"),
    include_links: z.boolean().optional(),
    include_images: z.boolean().optional(),
    main_content: z.boolean().optional().describe("Prefer <main>/<article>, drop nav/footer (default true)"),
    policy: policySchema,
  },
  async (a) => reply(await postJson(`${SR}/v1/read`, clean(a)))
);

server.tool(
  "grindfree_discovery",
  "Return machine-readable discovery URLs and unpaid 402 challenge shapes for all GrindFree agent-security APIs (no payment).",
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
      { name: "commandguard_command", url: `${CG}/v1/command`, body: { command: "ls -la" } },
      { name: "commandguard_sql", url: `${CG}/v1/sql`, body: { sql: "SELECT 1" } },
      { name: "memoryguard_screen", url: `${MG}/v1/screen`, body: { content: "User prefers metric units.", source: "user" } },
      { name: "wireshield_scan", url: `${WS}/v1/scan`, body: { content: "hello", format: "text" } },
      { name: "docshield_scan", url: `${DS}/v1/scan`, body: { content: "<p>hi</p>", format: "html" } },
      { name: "saferead_read", url: `${SR}/v1/read`, body: { url: "https://example.com/" } },
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
        origins: { promptshield: PS, crawlsafe: CS, toolguard: TG, commandguard: CG, memoryguard: MG, wireshield: WS, docshield: DS, saferead: SR },
        discovery: {
          well_known: ["/.well-known/x402", "/openapi.json", "/llms.txt"],
          payTo: "0xe4b5827994B7B3Cd38F9830d9ECF58b51B77721b",
          price_usdc: { promptshield: "0.002", crawlsafe: "0.002", toolguard: "0.002", commandguard: "0.001", memoryguard: "0.002", wireshield: "0.002", docshield: "0.004", saferead: "0.003" },
          network: "eip155:8453",
        },
        unpaid_probes: probes,
        payment_note:
          "Paid tools require caller X402_PRIVATE_KEY with Base USDC. Decisions are advisory: the caller must enforce block/deny.",
      },
      null,
      2
    );
    return { content: [{ type: "text", text }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

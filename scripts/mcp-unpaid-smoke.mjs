import { spawn } from "child_process";
import { createInterface } from "readline";

const child = spawn("node", ["mcp-server/src/index.js"], {
  cwd: "/workspace/grindfree-integrations",
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env }, // no PRIVATE_KEY
});

let id = 0;
function send(method, params) {
  id += 1;
  const msg = { jsonrpc: "2.0", id, method, params };
  child.stdin.write(JSON.stringify(msg) + "\n");
  return id;
}

const rl = createInterface({ input: child.stdout });
const pending = new Map();
rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id != null && pending.has(msg.id)) pending.get(msg.id)(msg);
  } catch {}
});

function wait(id) {
  return new Promise((resolve) => pending.set(id, resolve));
}

const initId = send("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0.0.1" },
});
const init = await wait(initId);
console.log("init", init.result?.serverInfo || init.error);

child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

const toolsId = send("tools/list", {});
const tools = await wait(toolsId);
console.log(
  "tools",
  (tools.result?.tools || []).map((t) => t.name)
);

const discId = send("tools/call", { name: "grindfree_discovery", arguments: {} });
const disc = await wait(discId);
const text = disc.result?.content?.[0]?.text || "";
console.log("discovery_ok", text.includes("promptshield") && text.includes("toolguard"));
console.log(text.slice(0, 600));

const missId = send("tools/call", {
  name: "promptshield_screen",
  arguments: { content: "hi", format: "text" },
});
const miss = await wait(missId);
const missText = miss.result?.content?.[0]?.text || "";
console.log("missing_key_msg", missText.includes("X402_PRIVATE_KEY"));

child.kill();
process.exit(0);

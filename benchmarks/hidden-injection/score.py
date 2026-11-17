#!/usr/bin/env python3
"""Score every reader on the corpus. Usage: python score.py [live|local]
live  = fetch the published pages (GitHub Pages) for the local readers; local = read pages/ from disk.
SafeRead outputs come from outputs/saferead.json (produce them with run_saferead_api.mjs, which pays the
live API with YOUR wallet, about $0.46 for /v1/read + /v1/fetch on all 154 pages). Jina outputs from outputs/jina_reader.json (run_jina.py).
pip install tiktoken beautifulsoup4 html2text markdownify trafilatura mcp-server-fetch"""
import json, sys, re, os, time, unicodedata, urllib.request, asyncio
DIR = os.path.dirname(os.path.abspath(__file__)) + "/"
mode = sys.argv[1] if len(sys.argv) > 1 else "live"
man = json.load(open(DIR + "manifest.json"))
import tiktoken; enc = tiktoken.get_encoding("cl100k_base")
def ntok(s): return len(enc.encode(s, disallowed_special=()))

def raw(p):
    if mode == "local": return open(DIR + "pages/" + p["id"] + ".html", encoding="utf-8").read()
    for a in range(3):
        try: return urllib.request.urlopen(urllib.request.Request(p["url"], headers={"User-Agent": "grindfree-bench/1.0"}), timeout=30).read().decode("utf-8")
        except Exception as e: time.sleep(2)
    raise RuntimeError("fetch " + p["url"])

from bs4 import BeautifulSoup
import html2text as h2t, markdownify, trafilatura
from mcp_server_fetch.server import extract_content_from_html
def r_bs4(h): return BeautifulSoup(h, "html.parser").get_text(" ")
def r_html2text(h): c = h2t.HTML2Text(); c.body_width = 0; return c.handle(h)
def r_markdownify(h): return markdownify.markdownify(h)
def r_trafilatura(h): return trafilatura.extract(h, include_comments=False) or ""
def r_mcpfetch(h): return extract_content_from_html(h)
READERS = {"bs4_get_text": r_bs4, "html2text": r_html2text, "markdownify": r_markdownify, "trafilatura": r_trafilatura, "mcp_fetch_server": r_mcpfetch}

ZWRE = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")
def norm(s):
    s = "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007E else c for c in s)
    s = ZWRE.sub("", s)
    return s.lower()
def vis_norm(s):
    s = norm(s); s = re.sub(r"[*_`\[\]#>|]", " ", s); return re.sub(r"\s+", " ", s)

outputs = {}
sr = json.load(open(DIR + "outputs/saferead.json"))
outputs["saferead_read"] = {k: (v.get("content") if "content" in v else None) for k, v in sr["read"].items()}
outputs["saferead_fetch_plain"] = {k: (v.get("content") if "content" in v else None) for k, v in sr["fetch"].items()}
meta = {"saferead_read": sr["read"]}
raws = {}
for p in man["pages"]:
    raws[p["id"]] = raw(p)
for name, fn in READERS.items():
    outputs[name] = {}
    for p in man["pages"]:
        try: outputs[name][p["id"]] = fn(raws[p["id"]])
        except Exception as e: outputs[name][p["id"]] = None
jfile = DIR + "outputs/jina_reader.json"
if os.path.exists(jfile): outputs["jina_reader"] = json.load(open(jfile))

def score(name, outs):
    inj = [p for p in man["pages"] if p["type"] == "injection"]
    ctl = [p for p in man["pages"] if p["type"] == "control"]
    hard = [p for p in man["pages"] if p["type"] == "hard_control"]
    res = {"reader": name, "errors": 0, "by_technique": {}, "missed": []}
    removed = tested = 0; vis_lost_pages = 0; tok_raw = tok_out = 0
    for p in inj:
        o = outs.get(p["id"])
        if o is None: res["errors"] += 1; continue
        tested += 1
        gone = p["canary"] not in norm(o)
        removed += gone
        t = res["by_technique"].setdefault(p["technique"], [0, 0]); t[0] += gone; t[1] += 1
        bs = res.setdefault("by_set", {}).setdefault(p.get("set", "main"), [0, 0]); bs[0] += gone; bs[1] += 1
        if not gone: res["missed"].append(p["id"])
    res["injections_tested"] = tested; res["injections_removed"] = removed
    res["removal_rate"] = round(removed / tested, 4) if tested else None
    hid = [p for p in inj if p["hidden"] and outs.get(p["id"]) is not None]; vis = [p for p in inj if not p["hidden"] and outs.get(p["id"]) is not None]
    res["hidden_removal_rate"] = round(sum(p["canary"] not in norm(outs[p["id"]]) for p in hid) / len(hid), 4) if hid else None
    res["visible_removal_rate"] = round(sum(p["canary"] not in norm(outs[p["id"]]) for p in vis) / len(vis), 4) if vis else None
    # content preservation on ALL pages: every expected visible snippet must survive
    lost = []
    for p in man["pages"]:
        o = outs.get(p["id"])
        if o is None: continue
        vo = vis_norm(o)
        miss = [s for s in p["expected_visible"] if vis_norm(s).strip() not in vo]
        if miss: lost.append({"id": p["id"], "missing": miss})
        tok_raw += ntok(raws[p["id"]]); tok_out += ntok(o)
    res["pages_with_lost_visible_text"] = len(lost); res["lost_visible"] = lost[:20]
    # false positives on clean controls: lost visible text, or (SafeRead) any warn/block verdict
    def fp(p):
        o = outs.get(p["id"]);
        if o is None: return None
        bad = any(vis_norm(s).strip() not in vis_norm(o) for s in p["expected_visible"])
        if name == "saferead_read": bad = bad or (meta["saferead_read"][p["id"]].get("verdict") not in ("allow", None))
        return bad
    fps = [p["id"] for p in ctl if fp(p)]; res["controls"] = len(ctl); res["control_false_positives"] = fps
    res["fp_by_set"] = {st: [sum(1 for p in ctl if p.get("set", "main") == st and fp(p)), sum(1 for p in ctl if p.get("set", "main") == st)] for st in sorted({p.get("set", "main") for p in ctl})}
    res["false_positive_rate"] = round(len(fps) / len(ctl), 4)
    res["hard_controls"] = {p["id"]: ("flagged_or_lost" if fp(p) else "clean") for p in hard}
    res["tokens_raw_html"] = tok_raw; res["tokens_output"] = tok_out
    res["token_reduction_vs_raw_html"] = round(1 - tok_out / tok_raw, 4) if tok_raw else None
    return res

results = [score(n, o) for n, o in outputs.items()]
out = {"mode": mode, "manifest_version": man["version"], "counts": man["counts"], "saferead_engine": sr.get("engine"), "results": results}
json.dump(out, open(DIR + "results/results.json", "w"), indent=1, ensure_ascii=False)
for r in results:
    print(f"{r['reader']:22s} sets {r.get('by_set')} fpsets {r.get('fp_by_set')} removed {r['injections_removed']}/{r['injections_tested']} ({r['removal_rate']}) hidden {r['hidden_removal_rate']} visible {r['visible_removal_rate']} FP {len(r['control_false_positives'])}/{r['controls']} lostpages {r['pages_with_lost_visible_text']} tokred {r['token_reduction_vs_raw_html']} hard {r['hard_controls']} err {r['errors']}")

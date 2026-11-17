import json, time, urllib.request, sys
import os
D = os.path.dirname(os.path.abspath(__file__)) + "/"
man = json.load(open(D + "manifest.json"))
out = {}
for i, p in enumerate(man["pages"]):
    txt = None
    for a in range(4):
        try:
            r = urllib.request.urlopen(urllib.request.Request("https://r.jina.ai/" + p["url"], headers={"User-Agent": "grindfree-bench/1.0", "X-No-Cache": "true"}), timeout=60)
            t = r.read().decode("utf-8", "replace")
            txt = t.split("Markdown Content:", 1)[1] if "Markdown Content:" in t else t
            break
        except Exception as e:
            print("retry", p["id"], e, flush=True); time.sleep(10 * (a + 1))
    out[p["id"]] = txt
    if i % 20 == 0: print(i, p["id"], (txt or "")[:60].replace("\n", " "), flush=True)
    time.sleep(3.2)
json.dump(out, open(D + "outputs/jina_reader.json", "w"))
print("done", sum(v is not None for v in out.values()), len(out))

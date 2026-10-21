"""After `bun run codex:blocks` on the overlaid checkout: mark the Authfly blocks done in xgen/schema/codex/blocks.json
(status and emptyMode are hand fields there; a new block starts as todo). emptyMode omit: with an empty list the widgets
leave the list out (providers, scopes, methods), they draw no empty state. Run codex:blocks again afterwards so the
screens that use them recompute. Also lifts the kit-block count of the codex test by the six Authfly blocks."""
import json, re, sys
from pathlib import Path

cg = Path(sys.argv[1])
p = cg / "xgen/schema/codex/blocks.json"
d = json.loads(p.read_text())
n = 0
for b in d["blocks"]:
    if b.get("spec", "").startswith("block.ak") and b.get("surface") == "kit-block":
        b["status"] = "done"
        if b.get("data"):
            b["emptyMode"] = "omit"
        n += 1
p.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
t = cg / "xgen/schema/test/codex-blocks.test.ts"
src = t.read_text()
src2 = re.sub(r"\[92, 15, 10, 2\] : \[92, 15, 0, 0\]", f"[{92 + n}, 15, 10, 2] : [{92 + n}, 15, 0, 0]", src)
t.write_text(src2)
print(f"codex-status: {n} Authfly blocks done; kit-block count {92 + n}")

#!/usr/bin/env python3
"""Keep the codegen dictionary ASCII for the Cyrillic specimen (upstream stores it as \\u escapes; the dictionary tools rewrite it)."""
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
p.write_text(re.sub(r"[\u0400-\u04FF]", lambda m: "\\u%04x" % ord(m.group()), s))

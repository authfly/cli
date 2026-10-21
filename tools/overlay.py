#!/usr/bin/env python3
"""Overlay the Authkit specs onto a pristine ui8kit/codegen checkout (never upstream): copies the organism and block
authoring files, registers them, merges the Authkit texts into the dictionary, adds a catalog category and a theme page."""
import json, re, shutil, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
cg = pathlib.Path(sys.argv[1])
A = cg / "xgen/screens/src/authoring"
shutil.copy(root / "specs/authoring/authkit.ts", A / "blocks/authkit.ts")
shutil.copy(root / "specs/authoring/blocks-authkit.ts", A / "gallery/blocks-authkit.ts")

def patch(path, old, new, once=True):
    s = path.read_text()
    if new in s: return
    if old not in s: sys.exit(f"overlay: anchor not found in {path}: {old[:60]}")
    path.write_text(s.replace(old, new, 1))

org = A / "blocks/organisms.ts"
patch(org, 'import { signupOrganisms } from "./signup";', 'import { signupOrganisms } from "./signup";\nimport { authkitOrganisms } from "./authkit";')
patch(org, "...guideOrganisms, ...signupOrganisms,", "...guideOrganisms, ...signupOrganisms, ...authkitOrganisms,")
bl = A / "gallery/blocks.ts"
patch(bl, 'import { vibeBlocks } from "./blocks-vibe";', 'import { vibeBlocks } from "./blocks-vibe";\nimport { authkitBlocks } from "./blocks-authkit";')
patch(bl, "...moreBlocks, ...vibeBlocks,", "...moreBlocks, ...vibeBlocks, ...authkitBlocks,")
cat = A / "gallery/catalog.ts"
patch(cat, 'cat("app-auth-pages", "Sign-in pages", ...all("authpage")),',
      'cat("app-auth-pages", "Sign-in pages", ...all("authpage")),\n    cat("app-authkit", "Authkit sign in and sign up", ...all("aksignin", "aksignup")),\n    cat("app-authkit-flows", "Authkit flows and account", ...all("akrequest", "aknotice", "akconsent", "akaccount")),')
th = A / "screens/themes.ts"
patch(th, '{ path: "profile", lead: "pagehead.start", head: ["Your profile",',
      '{ path: "akwidgets", lead: "pagehead.start", head: ["Authkit", "Sign-in widgets on Stalwart.", "Back to sign in"], rest: ["aksignin.password", "aksignin.email", "aksignin.username", "aksignin.magic", "aksignin.social", "aksignin.error", "aksignup.terms", "aksignup.taken"] },\n'
      '      { path: "akflows", lead: "pagehead.start", head: ["Authkit flows", "Requests, notices, consent and account.", "Back to sign in"], rest: ["akrequest.forgot", "akrequest.reset", "akrequest.code", "aknotice.check", "aknotice.verified", "aknotice.signout", "aknotice.error", "akconsent.default", "akaccount.default"] },\n'
      '      { path: "profile", lead: "pagehead.start", head: ["Your profile",')
en = cg / "xgen/content/ui/en.json"
d = json.loads(en.read_text())
d["authkit"] = json.loads((root / "specs/content/authkit.en.json").read_text())
en.write_text(json.dumps(d, indent=2, ensure_ascii=True) + "\n")
for f in (root / "specs/fixtures").glob("*.json"):
    shutil.copy(f, cg / "xgen/fixtures" / f.name)
print("overlay: ok")

// Screenshots of the key pages, light and dark, at 390 and 1440 px, into /workspace/authkit-shots (or SHOTS_DIR).
// Needs the compose stack, the site served on :4100 (bun run site:serve) and creds from `E2E_CREDS_OUT=... bun e2e/flow.test.ts`.
// Run: NODE_PATH=<dir with playwright-core> node e2e/screenshots.mjs /tmp/creds.json
import { chromium } from "playwright-core";
import { mkdirSync, readFileSync } from "node:fs";

const out = process.env.SHOTS_DIR ?? "/workspace/authkit-shots";
mkdirSync(out, { recursive: true });
const { addr, password } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const A = "http://localhost:4000", D = "http://localhost:5173", S = "http://localhost:4100";
const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox"] });

async function signedIn(ctx) {
  const p = await ctx.newPage();
  await p.goto(`${A}/auth/sign-in`);
  await p.fill('input[name="identifier"]', addr);
  await p.fill('input[name="password"]', password);
  await p.click('[data-testid="authkit-form"] button[type="submit"]');
  await p.waitForURL(`${A}/account`);
  return p;
}
const pages = [
  ["authkit-sign-in", (p) => p.goto(`${A}/auth/sign-in`)],
  ["authkit-sign-up", (p) => p.goto(`${A}/auth/sign-up`)],
  ["authkit-magic", (p) => p.goto(`${A}/auth/magic`)],
  ["authkit-forgot", (p) => p.goto(`${A}/auth/forgot`)],
  ["authkit-link-error", (p) => p.goto(`${A}/auth/magic/verify?token=bad`)],
  ["authkit-account", null],
  ["authkit-consent", null],
  ["demo-react", (p) => p.goto(D)],
  ["site-home", (p) => p.goto(`${S}/index.html`)],
  ["site-widgets", (p) => p.goto(`${S}/widgets.html`)],
  ["site-runtime-react", (p) => p.goto(`${S}/runtime-react.html`)],
];
for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  const ctx = await browser.newContext({ viewport: { width, height: 900 }, colorScheme: theme });
  await ctx.addInitScript((t) => localStorage.setItem("authkit-theme", t), theme);
  for (const [name, go] of pages) {
    let p;
    if (name === "authkit-account") p = await signedIn(ctx);
    else if (name === "authkit-consent") {
      p = await ctx.newPage();
      await p.goto(`${D}/login`);
      // the handoff asks for the password (Stalwart issues codes only for a password it checks)
      if (await p.locator('input[name="password"]').count()) {
        if (await p.locator('input[name="identifier"]').count()) await p.fill('input[name="identifier"]', addr);
        await p.fill('input[name="password"]', password);
        await p.click('[data-testid="authkit-form"] button[type="submit"]');
      }
      await p.waitForSelector('[data-testid="authkit-consent"]');
    } else { p = await ctx.newPage(); await go(p); }
    await p.waitForLoadState("networkidle");
    await p.screenshot({ path: `${out}/${name}-${theme}-${width}.png`, fullPage: true });
    await p.close();
  }
  await ctx.close();
}
await browser.close();
console.log(`screenshots: ${pages.length * 4} -> ${out}`);

// Authfly Console screenshots, light and dark, at 390 and 1440 px, into /workspace/authfly-shots/console-*.png.
// Needs the compose stack (console on 127.0.0.1:4500). Run: NODE_PATH=<dir with playwright-core> node e2e/console-shots.mjs
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";

const out = process.env.SHOTS_DIR ?? "/workspace/authfly-shots";
mkdirSync(out, { recursive: true });
const C = process.env.CONSOLE_URL ?? "http://localhost:4500";
const [user, pass] = (process.env.CONSOLE_ADMIN ?? "console:dev-only-console-password").split(":");
const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox"] });
const pages = [
  ["login", null],
  ["dashboard", "/"],
  ["users", "/users"],
  ["user", "USER"],
  ["object-oauth-clients", "/object?v=x:OAuthClient"],
  ["object-oidc-provider", "/object?v=x:OidcProvider"],
  ["explorer", "EXPLORER"],
  ["scenario-onboard", "/scenarios/onboard"],
  ["gdpr", "/gdpr"],
  ["erase-confirm", "ERASE"],
  ["logs", "/logs"],
];
let n = 0;
for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  const ctx = await browser.newContext({ viewport: { width, height: 900 }, colorScheme: theme });
  await ctx.addInitScript((t) => localStorage.setItem("authfly-theme", t), theme);
  const p = await ctx.newPage();
  await p.goto(`${C}/login`);
  await p.screenshot({ path: `${out}/console-login-${theme}-${width}.png`, fullPage: true }); n++;
  await p.fill('input[name="username"]', user);
  await p.fill('input[name="password"]', pass);
  await p.click('[data-testid="login-form"] button[type="submit"]');
  await p.waitForURL(`${C}/`);
  for (const [name, path] of pages.slice(1)) {
    if (path === "USER" || path === "ERASE") {
      await p.goto(`${C}/users`);
      const href = await p.locator('[data-testid="table"] a').first().getAttribute("href");
      await p.goto(C + href);
      if (path === "ERASE") await p.click('[data-testid="submit-user-erase"]');
    } else if (path === "EXPLORER") {
      await p.goto(`${C}/explorer?v=x:Domain&m=query`);
      await p.click('[data-testid="submit-send"]');
    } else await p.goto(C + path);
    await p.waitForLoadState("networkidle");
    await p.screenshot({ path: `${out}/console-${name}-${theme}-${width}.png`, fullPage: width === 1440 });
    n++;
  }
  await ctx.close();
}
await browser.close();
console.log(`${n} console screenshots in ${out}`);

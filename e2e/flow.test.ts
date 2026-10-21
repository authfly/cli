// End-to-end flow against the running docker compose stack (Stalwart + Authfly + React demo), headless HTTP:
// the real HTML forms (CSRF included), mail read back from Stalwart over JMAP as the new user.
//   docker compose up -d --build && bun e2e/flow.test.ts
const AUTHFLY = process.env.AUTHFLY_URL ?? "http://localhost:4000";
const DEMO = process.env.DEMO_URL ?? "http://localhost:5173";
const STALWART = process.env.STALWART_URL ?? "http://localhost:8080";
const DOMAIN = process.env.AUTHFLY_DOMAIN ?? "authfly.test";

let passed = 0;
const step = async (name: string, f: () => Promise<void>) => {
  const t = Date.now();
  try { await f(); passed++; console.log(`ok   ${name} (${Date.now() - t} ms)`); }
  catch (e) { console.log(`FAIL ${name}: ${(e as Error).message}`); process.exit(1); }
};
const assert = (c: unknown, m: string) => { if (!c) throw new Error(m); };

/** a browser: one cookie jar per host, no automatic redirects */
class Browser {
  jar = new Map<string, Map<string, string>>();
  async go(url: string, init: RequestInit = {}): Promise<{ res: Response; body: string; url: string }> {
    const u = new URL(url);
    const jar = this.jar.get(u.host) ?? new Map();
    const res = await fetch(url, { ...init, redirect: "manual", headers: { ...(init.headers ?? {}), Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const i = kv!.indexOf("=");
      const k = kv!.slice(0, i), v = kv!.slice(i + 1);
      if (/Max-Age=(0|-1)/.test(c) || v === "") jar.delete(k); else jar.set(k, v);
    }
    this.jar.set(u.host, jar);
    return { res, body: await res.text(), url };
  }
  /** follow redirects like a browser */
  async follow(url: string, init: RequestInit = {}) {
    let r = await this.go(url, init);
    for (let i = 0; i < 10 && r.res.status >= 300 && r.res.status < 400; i++) r = await this.go(new URL(r.res.headers.get("location")!, r.url).toString());
    return r;
  }
  /** submit the form of a page: hidden fields (csrf, token, decision) kept, fields overridden */
  async submit(page: { body: string; url: string }, fields: Record<string, string>, testid = "authfly-form", follow = true) {
    const forms = [...page.body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/g)];
    const form = forms.find((f) => f[1]!.includes(`data-testid="${testid}"`));
    assert(form, `no form ${testid} on ${page.url}`);
    const action = new URL(form![1]!.match(/action="([^"]*)"/)?.[1] ?? page.url, page.url).toString();
    const data = new URLSearchParams();
    for (const m of form![2]!.matchAll(/<input\b[^>]*type="hidden"[^>]*>/g)) {
      const name = m[0].match(/name="([^"]*)"/)?.[1], value = m[0].match(/value="([^"]*)"/)?.[1] ?? "";
      if (name) data.set(name, value.replace(/&amp;/g, "&"));
    }
    for (const [k, v] of Object.entries(fields)) data.set(k, v);
    const init = { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: data.toString() };
    return follow ? this.follow(action, init) : this.go(action, init);
  }
}

/** newest mail with a subject, read from Stalwart over JMAP as the account (urn:ietf:params:jmap:mail) */
async function mail(user: string, password: string, subject: string, after: number): Promise<string> {
  const auth = "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
  const session = (await (await fetch(`${STALWART}/jmap/session`, { headers: { Authorization: auth } })).json()) as { primaryAccounts: Record<string, string> };
  const accountId = session.primaryAccounts["urn:ietf:params:jmap:mail"];
  for (let i = 0; i < 40; i++) {
    const r = (await (await fetch(`${STALWART}/jmap`, { method: "POST", headers: { Authorization: auth, "Content-Type": "application/json" }, body: JSON.stringify({
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [["Email/query", { accountId, filter: { subject }, sort: [{ property: "receivedAt", isAscending: false }], limit: 1 }, "a"],
        ["Email/get", { accountId, "#ids": { resultOf: "a", name: "Email/query", path: "/ids" }, properties: ["subject", "receivedAt", "bodyValues", "textBody"], fetchTextBodyValues: true }, "b"]],
    }) })).json()) as { methodResponses: [string, { list?: { receivedAt: string; bodyValues: Record<string, { value: string }> }[] }][] };
    const m = r.methodResponses[1]?.[1].list?.[0];
    if (m && Date.parse(m.receivedAt) >= after - 2000) return Object.values(m.bodyValues).map((b) => b.value).join("\n");
    await Bun.sleep(500);
  }
  throw new Error(`no mail "${subject}" for ${user}`);
}
const linkIn = (text: string) => { const m = text.match(/https?:\/\/\S+/); assert(m, "no link in mail"); return m![0]; };
const has = (body: string, s: string) => assert(body.includes(s), `page lacks ${s}`);

async function waitUp(url: string) {
  for (let i = 0; i < 120; i++) { try { const r = await fetch(url, { redirect: "manual" }); if (r.status < 500) return; } catch {} await Bun.sleep(1000); }
  throw new Error(`${url} not up`);
}

const user = `e2e${Date.now().toString(36)}`;
const addr = `${user}@${DOMAIN}`;
let password = "First-Pass-1234";
const b = new Browser();
console.log(`Authfly e2e: ${AUTHFLY}, demo ${DEMO}, Stalwart ${STALWART}, user ${addr}`);

await step("stack is up (Stalwart discovery, Authfly, demo)", async () => {
  await waitUp(`${STALWART}/.well-known/openid-configuration`); await waitUp(`${AUTHFLY}/auth/sign-in`); await waitUp(`${DEMO}/`);
  const d = (await (await fetch(`${STALWART}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  assert(d.issuer && (d.code_challenge_methods_supported as string[]).includes("S256"), "discovery without S256");
});

await step("sign up creates the Stalwart account and shows check your email", async () => {
  const page = await b.follow(`${AUTHFLY}/auth/sign-up`);
  has(page.body, 'data-testid="authfly-sign-up"');
  const t = Date.now();
  const r = await b.submit(page, { name: "E2E Tester", username: user, password, terms: "on" });
  has(r.body, 'data-testid="authfly-notice"'); has(r.body, addr);
  (globalThis as { signupAt?: number }).signupAt = t;
});

await step("password sign-in is refused until the address is verified", async () => {
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: user, password });
  assert(r.res.status === 401, `status ${r.res.status}`); has(r.body, 'data-testid="authfly-error"');
});

await step("verification email arrives in the Stalwart mailbox (JMAP) and the link verifies", async () => {
  const text = await mail(addr, password, "Verify your email address", (globalThis as { signupAt?: number }).signupAt!);
  const r = await b.follow(linkIn(text));
  has(r.body, 'data-tone="success"'); has(r.body, "Email verified");
});

await step("magic link: request, read the email, follow the link, signed in", async () => {
  const page = await b.follow(`${AUTHFLY}/auth/magic`);
  const t = Date.now();
  const r = await b.submit(page, { identifier: addr });
  has(r.body, "Check your email");
  const link = linkIn(await mail(addr, password, "Your sign-in link", t));
  const acc = await b.follow(link);
  assert(acc.url.endsWith("/account"), `landed on ${acc.url}`);
  has(acc.body, 'data-testid="authfly-account"'); has(acc.body, addr); has(acc.body, "Signed in with a magic link");
  const again = await b.follow(link);
  has(again.body, 'data-tone="error"');
});

await step("sign out", async () => {
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-out`), {});
  has(r.body, "You are signed out");
  const acc = await b.follow(`${AUTHFLY}/account`);
  assert(acc.url.endsWith("/auth/sign-in"), "still signed in");
});

await step("username + password sign-in", async () => {
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: user, password });
  assert(r.url.endsWith("/account"), `landed on ${r.url}`); has(r.body, "Signed in with a password");
  await b.submit(await b.follow(`${AUTHFLY}/auth/sign-out`), {});
});

await step("email + password sign-in", async () => {
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: addr, password });
  assert(r.url.endsWith("/account"), `landed on ${r.url}`); has(r.body, addr);
  await b.submit(await b.follow(`${AUTHFLY}/auth/sign-out`), {});
});

await step("wrong password shows the error state", async () => {
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: addr, password: "wrong-password-123" });
  assert(r.res.status === 401, `status ${r.res.status}`); has(r.body, "The address or the password is wrong.");
});

await step("password reset: request, email, new password, old one refused", async () => {
  const t = Date.now();
  const r = await b.submit(await b.follow(`${AUTHFLY}/auth/forgot`), { email: addr });
  has(r.body, "Check your email");
  const link = linkIn(await mail(addr, password, "Reset your password", t));
  const form = await b.follow(link);
  has(form.body, 'data-testid="authfly-request"');
  const old = password;
  password = "Second-Pass-5678";
  const done = await b.submit(form, { password, confirm: password });
  has(done.body, "Password changed");
  const ok = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: user, password });
  assert(ok.url.endsWith("/account"), "new password refused");
  await b.submit(await b.follow(`${AUTHFLY}/auth/sign-out`), {});
  const bad = await b.submit(await b.follow(`${AUTHFLY}/auth/sign-in`), { identifier: user, password: old });
  assert(bad.res.status === 401, "old password still works");
});

await step("OIDC SSO into the React demo (authorization code + PKCE, Authfly hosted sign-in, consent)", async () => {
  const start = await b.follow(`${DEMO}/login`);
  assert(start.url.startsWith(`${AUTHFLY}/oauth/authorize?`), `not handed to Authfly: ${start.url}`);
  assert(start.url.includes("code_challenge_method=S256"), "no PKCE");
  const consent = await b.submit(start, { identifier: addr, password });
  has(consent.body, 'data-testid="authfly-consent"'); has(consent.body, "Demo app (React)");
  const back = await b.submit(consent, {}, "approve");
  assert(back.url === `${DEMO}/`, `landed on ${back.url}`);
  const me = await b.go(`${DEMO}/api/me`);
  assert(me.res.status === 200, `me ${me.res.status}`);
  const u = JSON.parse(me.body).user;
  assert(u.email === addr && u.amr === "oidc", `user ${me.body}`);
});

await step("OIDC deny returns access_denied to the demo", async () => {
  const d = new Browser();
  const start = await d.follow(`${DEMO}/login`);
  const consent = await d.submit(start, { identifier: addr, password });
  const back = await d.submit(consent, {}, "deny");
  assert(back.url.startsWith(`${DEMO}/?error=access_denied`), `landed on ${back.url}`);
});

await step("JSON API for adapters: sign-in token and /me", async () => {
  const r = await fetch(`${AUTHFLY}/api/v1/sign-in`, { method: "POST", body: JSON.stringify({ identifier: addr, password }) });
  const j = (await r.json()) as { token: string };
  assert(r.ok && j.token, "no token");
  const me = (await (await fetch(`${AUTHFLY}/api/v1/me`, { headers: { Authorization: `Bearer ${j.token}` } })).json()) as { user: { email: string } };
  assert(me.user.email === addr, "me mismatch");
});

/** run an adapter script (Python or PHP) that prints JSON */
async function run(cmd: string[], input: unknown): Promise<any> {
  const p = Bun.spawn(cmd, { stdin: new Blob([JSON.stringify(input)]), stdout: "pipe", stderr: "pipe", cwd: import.meta.dir });
  const [out, err, code] = [await new Response(p.stdout).text(), await new Response(p.stderr).text(), await p.exited];
  assert(code === 0, `${cmd.join(" ")} failed: ${err || out}`);
  return JSON.parse(out);
}
for (const [lang, cmd] of [["Python", ["python3", "adapters.py"]], ["PHP", ["php", "adapters.php"]]] as const) {
  await step(`${lang} adapter: OIDC (authorize URL, hosted sign-in, consent, code exchange at Stalwart) and JSON API`, async () => {
    const cfg = { authfly: AUTHFLY, stalwart: AUTHFLY /* OIDC endpoints through the Authfly proxy */, client: "adapters", redirect: "http://localhost:9999/callback", identifier: addr, password };
    const { url, pending } = await run([...cmd, "authorize"], cfg);
    const d = new Browser();
    const signin = await d.follow(url);
    const consent = await d.submit(signin, { identifier: addr, password });
    has(consent.body, "Adapter test");
    const back = await d.submit(consent, {}, "approve", false);
    const loc = back.res.headers.get("location") ?? "";
    assert(loc.startsWith(cfg.redirect + "?"), `redirect ${loc}`);
    const params = Object.fromEntries(new URL(loc).searchParams);
    const r = await run([...cmd, "callback"], { ...cfg, params, pending });
    assert(r.user.email === addr && r.user.aud && r.me.email === addr, `adapter result ${JSON.stringify(r)}`);
  });
}

// E2E_CREDS_OUT: leave the verified test account for e2e/screenshots.mjs
if (process.env.E2E_CREDS_OUT) await Bun.write(process.env.E2E_CREDS_OUT, JSON.stringify({ addr, password }));
console.log(`\n${passed} steps passed`);

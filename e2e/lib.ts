// Shared helpers of the e2e tests (a cookie-jar browser over fetch, mail over JMAP, steps).
export const AUTHKIT = process.env.AUTHKIT_URL ?? "http://localhost:4000";
export const STALWART = process.env.STALWART_URL ?? "http://localhost:8080";
export const CONSOLE = process.env.CONSOLE_URL ?? "http://localhost:4500";
export const DOMAIN = process.env.AUTHKIT_DOMAIN ?? "authkit.test";
export const ADMIN = process.env.STALWART_ADMIN ?? "admin:authkit-dev-admin";
export const CONSOLE_ADMIN = process.env.CONSOLE_ADMIN ?? "console:dev-only-console-password";

/** management JMAP as the Stalwart admin (to verify what the console and Authkit did) */
export async function jmap(calls: unknown[], using = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], auth = ADMIN) {
  const r = await fetch(`${STALWART}/jmap`, { method: "POST", headers: { Authorization: "Basic " + Buffer.from(auth).toString("base64"), "Content-Type": "application/json" }, body: JSON.stringify({ using, methodCalls: calls }) });
  if (r.status !== 200) throw new Error(`jmap HTTP ${r.status}`);
  return ((await r.json()) as { methodResponses: [string, any, string][] }).methodResponses;
}
export async function findAccount(name: string): Promise<any | undefined> {
  const r = await jmap([["x:Account/query", { filter: { name } }, "q"], ["x:Account/get", { "#ids": { resultOf: "q", name: "x:Account/query", path: "/ids" } }, "g"]]);
  return (r[1]![1].list as any[]).find((a) => a.name === name);
}
export const rand = () => Math.random().toString(36).slice(2, 8);

export let passed = 0;
export const step = async (name: string, f: () => Promise<void>) => {
  const t = Date.now();
  try { await f(); passed++; console.log(`ok   ${name} (${Date.now() - t} ms)`); }
  catch (e) { console.log(`FAIL ${name}: ${(e as Error).message}`); process.exit(1); }
};
export const assert = (c: unknown, m: string) => { if (!c) throw new Error(m); };

/** a browser: one cookie jar per host, no automatic redirects */
export class Browser {
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
  async submit(page: { body: string; url: string }, fields: Record<string, string>, testid = "authkit-form", follow = true) {
    const forms = [...page.body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/g)];
    const form = forms.find((f) => f[1]!.includes(`data-testid="${testid}"`));
    assert(form, `no form ${testid} on ${page.url}`);
    const action = new URL(form![1]!.match(/action="([^"]*)"/)?.[1] ?? page.url, page.url).toString();
    const data = new URLSearchParams();
    for (const m of form![2]!.matchAll(/<input\b[^>]*type="hidden"[^>]*>/g)) {
      const name = m[0].match(/name="([^"]*)"/)?.[1], value = m[0].match(/value="([^"]*)"/)?.[1] ?? "";
      if (name) data.set(name, unescapeHtml(value));
    }
    if (testid !== "authkit-form") {
      // like a browser: visible inputs and textareas with their values, selects with their selected option, checked boxes
      for (const m of form![2]!.matchAll(/<input\b[^>]*>/g)) {
        const t = m[0];
        const name = t.match(/name="([^"]*)"/)?.[1];
        if (!name || /type="(hidden|password|submit)"/.test(t) || /\sdisabled/.test(t)) continue;
        if (/type="(checkbox|radio)"/.test(t)) { if (/\schecked/.test(t)) data.set(name, unescapeHtml(t.match(/value="([^"]*)"/)?.[1] ?? "on")); continue; }
        data.set(name, unescapeHtml(t.match(/value="([^"]*)"/)?.[1] ?? ""));
      }
      for (const m of form![2]!.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g)) {
        const name = m[1]!.match(/name="([^"]*)"/)?.[1];
        if (name) data.set(name, unescapeHtml(m[2]!));
      }
      for (const m of form![2]!.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g)) {
        const name = m[1]!.match(/name="([^"]*)"/)?.[1];
        const opts = [...m[2]!.matchAll(/<option\b([^>]*)>/g)];
        const sel = opts.find((o) => /\sselected/.test(o[1]!)) ?? opts[0];
        if (name && sel) data.set(name, unescapeHtml(sel[1]!.match(/value="([^"]*)"/)?.[1] ?? ""));
      }
    }
    for (const [k, v] of Object.entries(fields)) data.set(k, v);
    const init = { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: data.toString() };
    return follow ? this.follow(action, init) : this.go(action, init);
  }
}

/** newest mail with a subject, read from Stalwart over JMAP as the account (urn:ietf:params:jmap:mail) */
export async function mail(user: string, password: string, subject: string, after: number): Promise<string> {
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
export const linkIn = (text: string) => { const m = text.match(/https?:\/\/\S+/); assert(m, "no link in mail"); return m![0]; };
export const has = (body: string, s: string) => assert(body.includes(s), `page lacks ${s}`);

export async function waitUp(url: string) {
  for (let i = 0; i < 120; i++) { try { const r = await fetch(url, { redirect: "manual" }); if (r.status < 500) return; } catch {} await Bun.sleep(1000); }
  throw new Error(`${url} not up`);
}

export const unescapeHtml = (v: string) => v.replace(/&#34;|&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

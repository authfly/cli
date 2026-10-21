// GDPR end to end against the compose stack: consent records, the self-service JSON export, erasure through the API
// and through the console, each verified in Stalwart (account, mailbox) and in Authfly (sessions, store, audit log).
//   docker compose up -d --build && bun e2e/gdpr.test.ts
import { AUTHFLY, assert, Browser, CONSOLE, CONSOLE_ADMIN, DOMAIN, findAccount, has, jmap, linkIn, mail, rand, step, STALWART } from "./lib";

const api = async (path: string, init: RequestInit & { token?: string } = {}) => {
  const r = await fetch(AUTHFLY + path, { ...init, headers: { "Content-Type": "application/json", ...(init.token ? { Authorization: `Bearer ${init.token}` } : {}) } });
  return { status: r.status, json: (await r.json().catch(() => ({}))) as any };
};
const docker = (cmd: string[]) => {
  const p = Bun.spawnSync(["sudo", "-n", "docker", "compose", "exec", "-T", ...cmd], { cwd: import.meta.dir + "/.." });
  return p.exitCode === 0 ? p.stdout.toString() : null;
};
const name = "gdpr-" + rand();
const addr = `${name}@${DOMAIN}`;
const password = "gdpr-pass-0123456";
let token = "";
let accountId = "";
let emailIds: string[] = [];

await step("sign up with terms consent, verify the address, sign in", async () => {
  const t0 = Date.now();
  const r = await api("/api/v1/sign-up", { method: "POST", body: JSON.stringify({ name: "Gdpr Person", username: name, password, terms: "2026-10" }) });
  assert(r.status === 201, `sign-up ${r.status} ${JSON.stringify(r.json)}`);
  const link = linkIn(await mail(addr, password, "Verify your email address", t0));
  const v = await api("/api/v1/verify-email", { method: "POST", body: JSON.stringify({ token: new URL(link).searchParams.get("token") }) });
  assert(v.status === 200, `verify ${v.status}`);
  const s = await api("/api/v1/sign-in", { method: "POST", body: JSON.stringify({ identifier: name, password }) });
  assert(s.status === 200, `sign-in ${s.status}`);
  token = s.json.token;
  accountId = (await findAccount(name)).id;
});
await step("consent record: terms version and time", async () => {
  const r = await api("/api/v1/me/consents", { token });
  assert(r.status === 200, `status ${r.status}`);
  const c = r.json.consents.find((x: any) => x.kind === "terms");
  assert(c && c.version === "2026-10" && c.granted && c.time, JSON.stringify(r.json));
});
await step("self-service export: account, Authfly records, audit trail, mailbox; no credentials", async () => {
  const r = await api("/api/v1/me/export", { token });
  assert(r.status === 200, `status ${r.status} ${JSON.stringify(r.json)}`);
  const e = r.json;
  assert(e.format === "authfly-export/1" && e.subject === addr, "header");
  assert(e.account?.emailAddress === addr && e.account.description === "Gdpr Person", "account record");
  assert(!("credentials" in e.account) && !JSON.stringify(e).includes(password), "credentials leaked");
  assert(e.authfly.email_verified_at && e.authfly.consents.length === 1, "authfly records");
  const actions = e.audit.map((x: any) => x.action);
  for (const a of ["sign_up", "verify_email", "sign_in"]) assert(actions.includes(a), `audit lacks ${a}`);
  assert(e.mailbox.mailboxes.length >= 1 && e.mailbox.emails.length >= 1, "mailbox empty");
  assert(e.mailbox.emails.some((m: any) => m.subject === "Verify your email address" && Object.values(m.bodyValues).length), "verification mail with body missing");
  emailIds = e.mailbox.emails.map((m: any) => m.id);
});
await step("console export of the same person is logged in both audit logs", async () => {
  const b = new Browser();
  const [u, p] = CONSOLE_ADMIN.split(":") as [string, string];
  await b.submit(await b.go(`${CONSOLE}/login`), { username: u, password: p }, "login-form", false);
  const r = await b.go(`${CONSOLE}/users/export?id=${accountId}`);
  assert(r.res.status === 200 && /attachment/.test(r.res.headers.get("content-disposition") ?? ""), `status ${r.res.status}`);
  assert(JSON.parse(r.body).account.emailAddress === addr, "export body");
  const logs = await b.go(`${CONSOLE}/logs?subject=${encodeURIComponent(addr)}`);
  has(logs.body, "console.gdpr.export");
  has(logs.body, "console:" + u); // Authfly's log names the console admin as actor
});
await step("erasure needs the password again", async () => {
  const r = await api("/api/v1/me", { method: "DELETE", token, body: JSON.stringify({ password: "wrong-password-1" }) });
  assert(r.status === 401, `status ${r.status}`);
  assert(await findAccount(name), "erased without password");
});
let report: any;
await step("self-service erasure", async () => {
  const r = await api("/api/v1/me", { method: "DELETE", token, body: JSON.stringify({ password }) });
  assert(r.status === 200, `status ${r.status} ${JSON.stringify(r.json)}`);
  report = r.json;
  assert(report.stalwartAccount === accountId && report.messagesBefore >= 1 && report.pseudonym.startsWith("erased:"), JSON.stringify(report));
  assert(report.verified === true && report.blobPurge === "scheduled", `verified ${report.verified} blobPurge ${report.blobPurge}`);
});
await step("verified in Stalwart: account gone, password rejected, mailbox gone", async () => {
  assert(!(await findAccount(name)), "account still listed");
  const g = await jmap([["x:Account/get", { ids: [accountId] }, "g"]]);
  assert(g[0]![1].list.length === 0 && g[0]![1].notFound.includes(accountId), "x:Account/get still returns it");
  const s = await fetch(`${STALWART}/jmap/session`, { headers: { Authorization: "Basic " + Buffer.from(`${addr}:${password}`).toString("base64") } });
  assert(s.status === 401, `user auth ${s.status}`);
  // the messages: not readable by id (as the admin, with impersonation), not found by full-text or subject search
  const m = await jmap([["Email/get", { accountId, ids: emailIds, properties: ["subject"] }, "g"], ["Email/query", { accountId, filter: { text: "verify" } }, "t"],
    ["Email/query", { accountId, filter: { subject: "Verify your email address" } }, "s"]], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);
  assert(m[0]![1].list.length === 0 && m[0]![1].notFound.length === emailIds.length, `messages readable: ${JSON.stringify(m[0])}`);
  assert(m[1]![1].ids.length === 0 && m[2]![1].ids.length === 0, "found by search");
});
await step("verified in Authfly: old session token revoked, no sign-in", async () => {
  const me = await api("/api/v1/me", { token });
  assert(me.status === 401, `session still valid: ${me.status}`);
  const s = await api("/api/v1/sign-in", { method: "POST", body: JSON.stringify({ identifier: name, password }) });
  assert(s.status === 401, `sign-in ${s.status}`);
});
await step("verified on disk: address gone from Authfly's store and audit log, pseudonym kept", async () => {
  const store = docker(["authfly", "cat", "/data/store.json"]);
  const audit = docker(["authfly", "cat", "/data/store-audit.jsonl"]);
  assert(store !== null && audit !== null, "docker exec unavailable");
  assert(!store!.includes(addr), "address in store.json");
  assert(!audit!.includes(addr), "address in the audit log");
  assert(audit!.includes(report.pseudonym) && audit!.includes('"action":"erase"'), "erasure not logged under pseudonym");
});
const name2 = "gdpr2-" + rand();
await step("a re-created address starts with an empty mailbox (nothing resurrected)", async () => {
  // re-use the erased name: a new account must not see the old mail
  const r = await api("/api/v1/sign-up", { method: "POST", body: JSON.stringify({ name: "Again", username: name, password }) });
  assert(r.status === 201, `sign-up ${r.status}`);
  const acc = await findAccount(name);
  assert(acc.id !== accountId, "same id reused");
  const m = await jmap([["Email/query", { accountId: acc.id, filter: { subject: "Verify your email address" } }, "q"], ["Email/get", { accountId: acc.id, "#ids": { resultOf: "q", name: "Email/query", path: "/ids" }, properties: ["receivedAt"] }, "g"]],
    ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:stalwart:jmap"]);
  const old = (m[1]![1].list as any[]).filter((x) => Date.parse(x.receivedAt) < Date.now() - 60_000);
  assert(old.length === 0, "old mail visible");
  void name2;
});
await step("console erasure: warning, typed confirmation, verified gone", async () => {
  const acc = await findAccount(name);
  const b = new Browser();
  const [u, p] = CONSOLE_ADMIN.split(":") as [string, string];
  await b.submit(await b.go(`${CONSOLE}/login`), { username: u, password: p }, "login-form", false);
  const page = await b.go(`${CONSOLE}/users/view?id=${acc.id}`);
  has(page.body, "right to erasure");
  const ask = await b.submit(page, {}, "form-user-erase");
  has(ask.body, "Destructive action");
  has(ask.body, "downloading the export first");
  const done = await b.submit(ask, { confirm: addr }, "form-confirm");
  has(done.body, "Erasure complete");
  assert(!done.body.includes('data-status="fail"'), "a step failed");
  has(done.body, "Verified: x:Account/get");
  assert(!(await findAccount(name)), "still in Stalwart");
});
console.log("\ngdpr e2e: all steps passed");

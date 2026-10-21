// Authfly Console end to end, against the compose stack: localhost-only binding, admin session, CSRF, schema-driven
// validation, user create/edit/delete (verified in Stalwart), generic object forms, request builder, saved requests,
// the onboarding scenario and the console audit log.
//   docker compose up -d --build && bun e2e/console.test.ts
import { assert, Browser, CONSOLE, DOMAIN, findAccount, has, jmap, rand, step, STALWART, CONSOLE_ADMIN, unescapeHtml } from "./lib";
import { networkInterfaces } from "node:os";

const [cuser, cpass] = CONSOLE_ADMIN.split(":") as [string, string];
const b = new Browser();
const name = "console-" + rand();
let uid = "";
const status = (r: { res: Response }) => r.res.status;
const publicIP = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal)?.address;

await step("console answers on localhost", async () => {
  const r = await b.go(`${CONSOLE}/login`);
  assert(status(r) === 200, `status ${status(r)}`);
  has(r.body, 'data-testid="login-form"');
});
await step("console is not published on the public interface", async () => {
  assert(publicIP, "no public IPv4 interface");
  let refused = false;
  try { await fetch(`http://${publicIP}:4500/login`, { signal: AbortSignal.timeout(3000) }); } catch { refused = true; }
  assert(refused, `4500 reachable on ${publicIP}`);
});
await step("unauthenticated pages redirect to sign-in; POST without session is refused", async () => {
  const r = await new Browser().go(`${CONSOLE}/users`);
  assert(status(r) === 303 && r.res.headers.get("location") === "/login", `status ${status(r)}`);
  const p = await new Browser().go(`${CONSOLE}/users/create`, { method: "POST" });
  assert(status(p) === 401, `POST status ${status(p)}`);
});
await step("login needs the CSRF token and the right password", async () => {
  const x = new Browser();
  const r = await x.go(`${CONSOLE}/login`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `username=${cuser}&password=${cpass}` });
  assert(status(r) === 403, `no csrf: ${status(r)}`);
  const page = await x.go(`${CONSOLE}/login`);
  const bad = await x.submit(page, { username: cuser, password: "wrong-password" }, "login-form", false);
  assert(status(bad) === 401, `wrong password: ${status(bad)}`);
  const ok = await b.submit(await b.go(`${CONSOLE}/login`), { username: cuser, password: cpass }, "login-form", false);
  assert(status(ok) === 303, `login: ${status(ok)}`);
  const cookie = ok.res.headers.getSetCookie().find((c) => c.startsWith("authfly_console="))!;
  assert(/HttpOnly/i.test(cookie) && /SameSite=Strict/i.test(cookie), "session cookie flags");
});
await step("dashboard: live lock-down checks all pass", async () => {
  const r = await b.go(`${CONSOLE}/`);
  assert(status(r) === 200, `status ${status(r)}`);
  has(r.body, "Lock-down status");
  assert(!r.body.includes('data-status="fail"'), "a lock-down check fails");
  assert((r.body.match(/data-status="ok"/g) ?? []).length >= 5, "fewer than 5 checks");
});
await step("POST without CSRF token, or cross-site, is refused", async () => {
  const r = await b.go(`${CONSOLE}/users/create`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `name=x&password=abcdefghijkl` });
  assert(status(r) === 403, `no csrf: ${status(r)}`);
  const page = await b.go(`${CONSOLE}/users`);
  const csrf = page.body.match(/name="csrf" value="([^"]+)"/)![1]!;
  const x = await b.go(`${CONSOLE}/users/create`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "cross-site" }, body: `csrf=${csrf}&name=x` });
  assert(status(x) === 403, `cross-site: ${status(x)}`);
});
await step("create user: schema validation rejects bad input, nothing is sent", async () => {
  const page = await b.go(`${CONSOLE}/users`);
  has(page.body, `${DOMAIN}`); // domains prefilled from live data
  const r = await b.submit(page, { name: "bad name!", password: "short" }, "form-user-create", false);
  assert(status(r) === 422, `status ${status(r)}`);
  assert((r.body.match(/data-testid="field-error"/g) ?? []).length >= 2, "field errors");
  assert(!(await findAccount("bad name!")), "account created anyway");
});
await step("create user through the console (verified in Stalwart)", async () => {
  const page = await b.go(`${CONSOLE}/users`);
  const r = await b.submit(page, { name, description: "Console Test", password: "console-pass-0123" }, "form-user-create", false);
  assert(status(r) === 303, `status ${status(r)}`);
  uid = new URL(r.res.headers.get("location")!, CONSOLE).searchParams.get("id")!;
  const acc = await findAccount(name);
  assert(acc && acc.id === uid && acc.description === "Console Test" && acc.emailAddress === `${name}@${DOMAIN}`, "account in Stalwart");
  const view = await b.go(`${CONSOLE}/users/view?id=${uid}&created=1`);
  has(view.body, "User created");
  has(view.body, `${name}@${DOMAIN}`);
});
await step("the new user can sign in to Stalwart with the console-set password", async () => {
  const r = await fetch(`${STALWART}/jmap/session`, { headers: { Authorization: "Basic " + Buffer.from(`${name}@${DOMAIN}:console-pass-0123`).toString("base64") } });
  assert(r.status === 200, `session ${r.status}`);
});
await step("edit user: name and password (verified in Stalwart)", async () => {
  const page = await b.go(`${CONSOLE}/users/view?id=${uid}`);
  const r = await b.submit(page, { description: "Console Edited", password: "console-pass-4567" }, "form-user-edit");
  has(r.body, "Saved");
  assert((await findAccount(name)).description === "Console Edited", "description not updated");
  const old = await fetch(`${STALWART}/jmap/session`, { headers: { Authorization: "Basic " + Buffer.from(`${name}@${DOMAIN}:console-pass-0123`).toString("base64") } });
  const neu = await fetch(`${STALWART}/jmap/session`, { headers: { Authorization: "Basic " + Buffer.from(`${name}@${DOMAIN}:console-pass-4567`).toString("base64") } });
  assert(old.status === 401 && neu.status === 200, `old ${old.status} new ${neu.status}`);
});
await step("delete user: warning and typed confirmation, then gone from Stalwart", async () => {
  const page = await b.go(`${CONSOLE}/users/view?id=${uid}`);
  const ask = await b.submit(page, {}, "form-user-delete");
  has(ask.body, "Destructive action");
  has(ask.body, "This cannot be undone.");
  const wrong = await b.submit(ask, { confirm: "nope" }, "form-confirm", false);
  assert(status(wrong) === 422, `wrong confirm ${status(wrong)}`);
  assert(await findAccount(name), "deleted without confirmation");
  const done = await b.submit(ask, { confirm: `${name}@${DOMAIN}` }, "form-confirm");
  has(done.body, "was deleted");
  assert(!(await findAccount(name)), "still in Stalwart");
});
const client = "console-client-" + rand();
let clientId = "";
await step("generic schema form: invalid JSON rejected, OAuth client created", async () => {
  const page = await b.go(`${CONSOLE}/object?v=x:OAuthClient`);
  has(page.body, "Dependencies");
  has(page.body, "requireClientRegistration");
  const bad = await b.submit(page, { clientId: client, redirectUris: "{not json" }, "form-create", false);
  assert(status(bad) === 422, `status ${status(bad)}`);
  has(bad.body, "invalid JSON");
  const ok = await b.submit(page, { clientId: client, description: "from console", redirectUris: '{"http://localhost:7777/cb": true}' }, "form-create");
  has(ok.body, "Created");
  const r = await jmap([["x:OAuthClient/query", {}, "q"], ["x:OAuthClient/get", { "#ids": { resultOf: "q", name: "x:OAuthClient/query", path: "/ids" } }, "g"]]);
  const c = (r[1]![1].list as any[]).find((x) => x.clientId === client);
  assert(c && c.redirectUris["http://localhost:7777/cb"], "client not in Stalwart");
  clientId = c.id;
});
await step("generic schema form: edit sends only the changed field, delete asks first", async () => {
  const page = await b.go(`${CONSOLE}/object/edit?v=x:OAuthClient&id=${clientId}`);
  const r = await b.submit(page, { description: "edited in console" }, "form-edit");
  has(r.body, "Saved");
  has(r.body, "description");
  const ask = await b.submit(await b.go(`${CONSOLE}/object/edit?v=x:OAuthClient&id=${clientId}`), {}, "form-destroy");
  has(ask.body, "Type " + client);
  await b.submit(ask, { confirm: client }, "form-confirm");
  const g = await jmap([["x:OAuthClient/get", { ids: [clientId] }, "g"]]);
  assert((g[0]![1].list as any[]).length === 0, "client still exists");
});
await step("request builder: template, send, response, curl export, saved request", async () => {
  const page = await b.go(`${CONSOLE}/explorer?v=x:Domain&m=query`);
  has(page.body, "x:Domain/query");
  const sent = await b.submit(page, {}, "form-send");
  has(sent.body, "Response: HTTP 200");
  has(sent.body, "methodResponses");
  has(sent.body, "curl -sS");
  const saved = await b.submit(sent, { name: "domains " + rand() }, "form-save");
  has(saved.body, "Saved requests");
  has(saved.body, "x:Domain query");
});
await step("request builder: invalid JSON is not sent; destroy needs confirmation", async () => {
  const page = await b.go(`${CONSOLE}/explorer?v=x:Domain&m=query`);
  const bad = await b.submit(page, { body: "{oops" }, "form-send", false);
  assert(status(bad) === 422, `status ${status(bad)}`);
  has(bad.body, "Not sent");
  const d = await b.submit(page, { body: JSON.stringify({ using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], methodCalls: [["x:Domain/set", { destroy: ["does-not-exist"] }, "0"]] }) }, "form-send", false);
  has(d.body, "Type destroy to confirm");
});
const oname = "onboard-" + rand();
await step("scenario: create user + OIDC client + real test sign-in, all steps pass", async () => {
  const page = await b.go(`${CONSOLE}/scenarios/onboard`);
  const r = await b.submit(page, { name: oname, password: "onboard-pass-0123", clientId: "app-" + oname, redirect: "http://localhost:7000/callback" }, "form-onboard", false);
  assert(status(r) === 200, `status ${status(r)}: ${unescapeHtml(r.body.match(/data-status="fail"[\s\S]{0,400}/)?.[0]?.replace(/<[^>]+>/g, " ") ?? "")}`);
  assert((r.body.match(/data-status="ok"/g) ?? []).length === 6, "not 6 ok steps");
  has(r.body, "signature valid");
  // clean up
  const acc = await findAccount(oname);
  const cl = await jmap([["x:OAuthClient/query", {}, "q"], ["x:OAuthClient/get", { "#ids": { resultOf: "q", name: "x:OAuthClient/query", path: "/ids" } }, "g"]]);
  const c = (cl[1]![1].list as any[]).find((x) => x.clientId === "app-" + oname);
  await jmap([["x:Account/set", { destroy: [acc.id] }, "a"], ["x:OAuthClient/set", { destroy: [c.id] }, "b"]]);
});
await step("console audit log records the actions, hash chain intact", async () => {
  const r = await b.go(`${CONSOLE}/logs`);
  for (const a of ["console.login", "console.user.create", "console.user.update", "console.user.delete", "console.object.create", "console.object.destroy", "console.explorer.send", "console.scenario.onboard", "console.csrf"]) has(r.body, a);
  has(r.body, "hash chain intact");
});
await step("every schema view renders (143 objects, no server errors)", async () => {
  const dash = await b.go(`${CONSOLE}/`);
  const views = [...new Set([...dash.body.matchAll(/href="(\/object\?v=[^"]+)"/g)].map((m) => unescapeHtml(m[1]!)))];
  assert(views.length > 100, `only ${views.length} views`);
  for (const v of views) {
    const r = await b.go(CONSOLE + v);
    assert(status(r) === 200, `${v}: ${status(r)}`);
    assert(!r.body.includes('data-testid="alert-destructive"'), `${v}: error`);
  }
});
await step("sign out ends the session", async () => {
  const page = await b.go(`${CONSOLE}/`);
  const csrf = page.body.match(/name="csrf" value="([^"]+)"/)![1]!;
  await b.go(`${CONSOLE}/logout`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `csrf=${csrf}` });
  const r = await b.go(`${CONSOLE}/`);
  assert(status(r) === 303, `after logout ${status(r)}`);
});
console.log(`\nconsole e2e: all steps passed`);

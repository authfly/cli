// Lock-down test: Stalwart management is not reachable from the public network, only the mail ports and the OIDC
// endpoints Authfly proxies are. Run against the compose stack: bun e2e/security.test.ts
import { connect } from "node:net";
import { networkInterfaces } from "node:os";

const AUTHFLY = process.env.AUTHFLY_URL ?? "http://localhost:4000";
const LOCAL = process.env.STALWART_URL ?? "http://localhost:8080"; // localhost-only binding
const SVC = process.env.AUTHFLY_SERVICE ?? "authfly-svc@authfly.test:dev-only-service-password-0123";
const ADMIN = process.env.STALWART_ADMIN ?? "admin:authfly-dev-admin";
let passed = 0;
const step = async (name: string, f: () => Promise<void>) => {
  const t = Date.now();
  try { await f(); passed++; console.log(`ok   ${name} (${Date.now() - t} ms)`); } catch (e) { console.log(`FAIL ${name}\n     ${(e as Error).message}`); process.exit(1); }
};
const assert = (c: unknown, m: string) => { if (!c) throw new Error(m); };
const basic = (c: string) => `Basic ${Buffer.from(c).toString("base64")}`;
/** the machine's address on the network (not loopback): what the public reaches */
const publicIp = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal && !i.address.startsWith("172."))?.address
  ?? Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal)!.address;
const tcp = (host: string, port: number) => new Promise<"open" | "closed">((res) => {
  const s = connect({ host, port, timeout: 3000 });
  s.on("connect", () => { s.destroy(); res("open"); }).on("error", () => res("closed")).on("timeout", () => { s.destroy(); res("closed"); });
});
const jmap = (cred: string, calls: unknown[]) => fetch(`${LOCAL}/jmap`, { method: "POST", headers: { Authorization: basic(cred), "Content-Type": "application/json" },
  body: JSON.stringify({ using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], methodCalls: calls }) }).then((r) => r.json() as Promise<{ methodResponses: [string, any, string][] }>);

console.log(`security e2e: public address ${publicIp}`);

await step(`Stalwart HTTP (management) is closed on the public address ${publicIp}:8080`, async () => {
  assert((await tcp(publicIp, 8080)) === "closed", "8080 reachable from the network");
});
await step("Stalwart HTTP answers on localhost only (for the ssh tunnel)", async () => {
  assert((await tcp("127.0.0.1", 8080)) === "open", "8080 not on localhost");
});
await step("Authfly Console is closed on the public address, open on localhost", async () => {
  assert((await tcp(publicIp, 4500)) === "closed", "4500 reachable from the network");
  assert((await tcp("127.0.0.1", 4500)) === "open", "4500 not on localhost");
  const r = await fetch("http://127.0.0.1:4500/login");
  assert(r.status === 200 && (await r.text()).includes("Authfly Console"), `console login ${r.status}`);
});
await step("Authfly's internal admin API (:4001) is not published at all", async () => {
  assert((await tcp(publicIp, 4001)) === "closed" && (await tcp("127.0.0.1", 4001)) === "closed", "4001 reachable from the host");
});
await step("mail ports are public (SMTP 2525, submissions 4465, IMAPS 9993)", async () => {
  assert((await tcp(publicIp, 2525)) === "open" && (await tcp(publicIp, 4465)) === "open" && (await tcp(publicIp, 9993)) === "open", "mail port closed");
});
await step("through Authfly, no Stalwart management or account API: /jmap, /api/*, /admin, /login, /auth/register, /auth/device, /auth/introspect", async () => {
  for (const [m, p] of [["POST", "/jmap"], ["GET", "/jmap/session"], ["GET", "/api/account"], ["POST", "/api/auth"], ["GET", "/api/schema"], ["GET", "/admin"],
    ["GET", "/login"], ["POST", "/auth/register"], ["POST", "/auth/device"], ["POST", "/auth/introspect"], ["GET", "/healthz/live"]] as const) {
    const r = await fetch(`${AUTHFLY}${p}`, { method: m, headers: { Authorization: basic(ADMIN), "Content-Type": "application/json" }, body: m === "POST" ? "{}" : undefined, redirect: "manual" });
    assert(r.status === 404 || r.status === 405, `${m} ${p} answered ${r.status} through Authfly`);
  }
});
await step("through Authfly, the OIDC endpoints work: discovery (issuer = Authfly, authorize = hosted sign-in, no registration/device), JWKS", async () => {
  const d = (await (await fetch(`${AUTHFLY}/.well-known/openid-configuration`)).json()) as Record<string, string>;
  assert(d.issuer === AUTHFLY, `issuer ${d.issuer}`);
  assert(d.authorization_endpoint === `${AUTHFLY}/oauth/authorize`, `authorize ${d.authorization_endpoint}`);
  assert(!d.registration_endpoint && !d.device_authorization_endpoint, "registration or device endpoint advertised");
  const j = (await (await fetch(`${AUTHFLY}/auth/jwks.json`)).json()) as { keys: unknown[] };
  assert(j.keys.length > 0, "no keys");
});
await step("Stalwart web admin and self-service UI are disabled (404 even on localhost)", async () => {
  for (const p of ["/admin/", "/account/"]) {
    const r = await fetch(`${LOCAL}${p}`, { redirect: "manual" });
    assert(r.status === 404, `${p} ${r.status}`);
  }
});
await step("anonymous dynamic client registration is refused, unregistered client ids are refused", async () => {
  const r = await fetch(`${LOCAL}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://evil.invalid/cb"], client_name: "x" }) });
  assert(r.status >= 400, `registration answered ${r.status}`);
  const [user, pass] = SVC.split(":");
  const a = await fetch(`${LOCAL}/api/auth`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "authCode", accountName: user, accountSecret: pass, clientId: "not-registered", redirectUri: "http://localhost:9/cb" }) });
  const body = await a.text();
  assert(!body.includes("client_code") && !body.includes("clientCode"), `unregistered client got a code: ${a.status} ${body}`);
});
await step("Authfly's service account is least privilege: accounts yes; settings, roles, queue, logs, OIDC config no", async () => {
  const r = await jmap(SVC, [["x:Account/query", { limit: 1 }, "a"], ["x:Http/get", { ids: ["singleton"] }, "b"], ["x:Role/query", {}, "c"],
    ["x:QueuedMessage/query", {}, "d"], ["x:OidcProvider/get", { ids: ["singleton"] }, "e"], ["x:Application/query", {}, "f"]]);
  const by = Object.fromEntries(r.methodResponses.map((m) => [m[2], m[0]]));
  assert(by.a === "x:Account/query", "service cannot manage accounts");
  for (const k of ["b", "c", "d", "e", "f"]) assert(by[k] === "error", `service account reached call ${k}`);
});
await step("the service account cannot escalate: creating an admin account is refused", async () => {
  const r = await jmap(SVC, [["x:Account/set", { create: { x: { "@type": "User", name: `esc${Date.now()}`, domainId: "b", roles: { "@type": "Admin" }, permissions: { "@type": "Inherit" },
    credentials: { "0": { "@type": "Password", secret: "Escalate-Pass-123456" } }, encryptionAtRest: { "@type": "Disabled" } } } }, "a"]]);
  assert(r.methodResponses[0]![1].notCreated?.x?.type === "forbidden", `escalation: ${JSON.stringify(r.methodResponses[0])}`);
});
console.log(`\n${passed} security steps passed`);

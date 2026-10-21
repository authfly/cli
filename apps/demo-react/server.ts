// The demo's backend for frontend (Bun): serves the built SPA and the OIDC routes through @authkit/node.
import { Authkit, cookie, setCookie } from "@authkit/node";
import { join } from "node:path";

const env = (k: string, d: string) => process.env[k] ?? d;
const ak = new Authkit({
  authkitUrl: env("AUTHKIT_URL", "http://localhost:4000"),
  stalwartUrl: env("STALWART_URL", "http://localhost:8080"),
  clientId: env("OIDC_CLIENT_ID", "demo-react"),
  redirectUri: env("OIDC_REDIRECT_URI", "http://localhost:5173/callback"),
  sessionSecret: env("SESSION_SECRET", "demo-react-session-secret-change-me-0123"),
});
const dist = join(import.meta.dir, "dist");
const redirect = (to: string, cookies: string[] = []) => {
  const h = new Headers({ Location: to });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(null, { status: 303, headers: h });
};

Bun.serve({
  port: Number(env("PORT", "5173")),
  async fetch(req) {
    const url = new URL(req.url);
    const ck = req.headers.get("cookie");
    if (url.pathname === "/login") {
      const { url: to, pending } = await ak.authorizeUrl();
      return redirect(to, [setCookie("demo_pending", await ak.seal({ ...pending, exp: Math.floor(Date.now() / 1000) + 900 }), 900)]);
    }
    if (url.pathname === "/callback") {
      try {
        const pending = await ak.unseal<{ state: string; verifier: string; nonce: string }>(cookie(ck, "demo_pending"));
        const { user } = await ak.callback(url.searchParams, pending!);
        return redirect("/", [setCookie("demo_session", await ak.seal(user), 12 * 3600), setCookie("demo_pending", "", 0)]);
      } catch (e) {
        console.error("callback:", (e as Error).message);
        return redirect(`/?error=${encodeURIComponent(url.searchParams.get("error") ?? "sign_in_failed")}`, [setCookie("demo_pending", "", 0)]);
      }
    }
    if (url.pathname === "/logout" && req.method === "POST") return redirect("/", [setCookie("demo_session", "", 0)]);
    if (url.pathname === "/api/me") {
      const user = await ak.unseal(cookie(ck, "demo_session"));
      return user ? Response.json({ user }) : Response.json({ error: "unauthenticated" }, { status: 401 });
    }
    const file = Bun.file(join(dist, url.pathname === "/" ? "index.html" : url.pathname));
    return (await file.exists()) ? new Response(file) : new Response(Bun.file(join(dist, "index.html")));
  },
});
console.log("demo-react on", env("PORT", "5173"));

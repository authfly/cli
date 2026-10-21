// @authfly/node: the adapter of the TypeScript runtime family. Server-side only (it holds the session secret).
// - OIDC relying party: authorization code + PKCE; the browser signs in on the Authfly hosted page (or Stalwart's own
//   /login), the code is exchanged at Stalwart's token endpoint, the ID token (ES256) is verified with Stalwart's JWKS.
// - Sessions: HMAC-SHA256 signed cookies.
// - AuthflyApi: the Authfly JSON API (sign-up, password sign-in, magic link, reset) for custom forms.
const enc = new TextEncoder();
const b64url = (b: ArrayBuffer | Uint8Array) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("base64url");
const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

export interface AuthflyOptions {
  /** public URL of the Authfly server (browser-facing), e.g. http://localhost:4000 */
  authflyUrl: string;
  /** URL the server uses to reach Stalwart (token endpoint, JWKS), e.g. http://stalwart:8080 */
  stalwartUrl: string;
  clientId: string;
  redirectUri: string;
  /** at least 32 characters */
  sessionSecret: string;
  scope?: string;
  /** "authfly" (default): the Authfly hosted sign-in; "stalwart": Stalwart's own /login page */
  loginVia?: "authfly" | "stalwart";
}

export interface User { sub: string; email: string; name: string; username: string; amr: string; exp: number }
export interface Pending { state: string; verifier: string; nonce: string }

export class Authfly {
  constructor(readonly o: AuthflyOptions) {
    if (o.sessionSecret.length < 32) throw new Error("sessionSecret must have at least 32 characters");
  }

  /** where to send the browser, and what to keep (signed) until the callback */
  async authorizeUrl(): Promise<{ url: string; pending: Pending }> {
    const verifier = rand(32), state = rand(16), nonce = rand(16);
    const challenge = b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
    const base = this.o.loginVia === "stalwart" ? (await this.discovery()).authorization_endpoint : `${this.o.authflyUrl.replace(/\/$/, "")}/oauth/authorize`;
    const q = new URLSearchParams({ response_type: "code", client_id: this.o.clientId, redirect_uri: this.o.redirectUri, scope: this.o.scope ?? "openid email profile", state, nonce, code_challenge: challenge, code_challenge_method: "S256" });
    return { url: `${base}?${q}`, pending: { state, verifier, nonce } };
  }

  /** finish the flow: check state, exchange the code, verify the ID token */
  async callback(params: URLSearchParams, pending: Pending): Promise<{ user: User; tokens: Record<string, unknown> }> {
    if (params.get("error")) throw new Error(`authorization failed: ${params.get("error")}`);
    if (!pending || params.get("state") !== pending.state) throw new Error("state mismatch");
    const res = await fetch(`${this.o.stalwartUrl.replace(/\/$/, "")}/auth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: params.get("code") ?? "", client_id: this.o.clientId, redirect_uri: this.o.redirectUri, code_verifier: pending.verifier }),
    });
    const tokens = (await res.json()) as Record<string, string>;
    if (!res.ok || !tokens.id_token) throw new Error(`token exchange failed: ${res.status} ${JSON.stringify(tokens)}`);
    const claims = await this.verifyIdToken(tokens.id_token, pending.nonce);
    const email = String(claims.email ?? claims.preferred_username ?? "");
    const user: User = { sub: String(claims.sub), email, name: String(claims.name ?? claims.description ?? ""), username: email.split("@")[0]!, amr: "oidc", exp: Math.floor(Date.now() / 1000) + 12 * 3600 };
    return { user, tokens };
  }

  private disco?: Record<string, string>;
  async discovery(): Promise<Record<string, string>> {
    if (!this.disco) this.disco = (await (await fetch(`${this.o.stalwartUrl.replace(/\/$/, "")}/.well-known/openid-configuration`)).json()) as Record<string, string>;
    return this.disco;
  }

  async verifyIdToken(jwt: string, nonce?: string): Promise<Record<string, unknown>> {
    const [h, p, s] = jwt.split(".");
    if (!h || !p || !s) throw new Error("id_token malformed");
    const header = JSON.parse(Buffer.from(h, "base64url").toString());
    if (header.alg !== "ES256") throw new Error(`id_token alg ${header.alg} not supported (configure ES256 on Stalwart)`);
    const jwks = (await (await fetch(`${this.o.stalwartUrl.replace(/\/$/, "")}/auth/jwks.json`)).json()) as { keys: JsonWebKey[] & { kid?: string }[] };
    const jwk = (jwks.keys as (JsonWebKey & { kid?: string })[]).find((k) => k.kid === header.kid) ?? jwks.keys[0];
    const key = await crypto.subtle.importKey("jwk", { kty: jwk!.kty, crv: jwk!.crv, x: jwk!.x, y: jwk!.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), enc.encode(`${h}.${p}`));
    if (!ok) throw new Error("id_token signature invalid");
    const c = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
    const d = await this.discovery();
    if (c.iss !== d.issuer) throw new Error(`id_token issuer ${c.iss} != ${d.issuer}`);
    if (c.aud !== this.o.clientId) throw new Error("id_token audience mismatch");
    if (typeof c.exp !== "number" || c.exp < Date.now() / 1000) throw new Error("id_token expired");
    if (nonce && c.nonce !== nonce) throw new Error("id_token nonce mismatch");
    return c;
  }

  // ---- signed values (session cookie, pending flow cookie)
  private async hmac(data: string): Promise<string> {
    const key = await crypto.subtle.importKey("raw", enc.encode(this.o.sessionSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
  }
  async seal(value: unknown): Promise<string> {
    const p = Buffer.from(JSON.stringify(value)).toString("base64url");
    return `${p}.${await this.hmac(p)}`;
  }
  async unseal<T>(token: string | undefined): Promise<T | null> {
    if (!token) return null;
    const i = token.lastIndexOf(".");
    if (i < 0 || (await this.hmac(token.slice(0, i))) !== token.slice(i + 1)) return null;
    const v = JSON.parse(Buffer.from(token.slice(0, i), "base64url").toString()) as T & { exp?: number };
    if (v.exp && v.exp < Date.now() / 1000) return null;
    return v;
  }
}

/** read one cookie from a Cookie header */
export const cookie = (header: string | null, name: string) => header?.split(/;\s*/).find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1);
export const setCookie = (name: string, value: string, maxAge: number, secure = false) =>
  `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;

/** client of the Authfly JSON API (server to server) */
export class AuthflyApi {
  constructor(readonly baseUrl: string, readonly apiKey = "") {}
  private async call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}/api/v1${path}`, {
      method, headers: { "Content-Type": "application/json", ...(this.apiKey ? { "X-Authfly-Key": this.apiKey } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const out = (await res.json()) as T & { error?: string; message?: string };
    if (!res.ok) throw Object.assign(new Error(out.message ?? out.error ?? String(res.status)), { code: out.error, status: res.status });
    return out;
  }
  signUp = (name: string, username: string, password: string) => this.call<{ user: unknown }>("POST", "/sign-up", { name, username, password });
  signIn = (identifier: string, password: string) => this.call<{ token: string; user: unknown }>("POST", "/sign-in", { identifier, password });
  requestMagicLink = (identifier: string) => this.call<{ sent_to: string }>("POST", "/magic-link", { identifier });
  verifyMagicLink = (token: string) => this.call<{ token: string; user: unknown }>("POST", "/magic-link/verify", { token });
  verifyEmail = (token: string) => this.call("POST", "/verify-email", { token });
  forgot = (email: string) => this.call<{ sent_to: string }>("POST", "/forgot", { email });
  reset = (token: string, password: string) => this.call("POST", "/reset", { token, password });
  me = (token: string) => this.call<{ user: unknown }>("GET", "/me", undefined, token);
}

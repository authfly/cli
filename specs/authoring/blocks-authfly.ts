// Authfly blocks: each Authfly organism with its named variants (the parity cases of all eight runtimes and the live previews
// of the docs site). Overlaid to xgen/screens/src/authoring/gallery/blocks-authfly.ts by tools/gen-ui.sh.
import { define } from "./blocks-define";
import { t } from "./block-kit";
import type { Source } from "./block-kit";
import { ref } from "../../build";
import { CODEX_FIELDS } from "../../../../runtimes/core/assets/app/fields";

const src = (as: string, kind: string): Source => ({ as, collection: as, kind, record: "Feature", fields: { ...CODEX_FIELDS.feature } });
const providers = src("akproviders", "channel"), scopes = src("akscopes", "feature"), methods = src("akmethods", "perk");

const k = (p: string) => t(`authfly.${p}`);
const page = (p: string) => ({ title: k(`${p}.title`), text: k(`${p}.text`) });

const signin = define({
  key: "aksignin", theme: "account", group: "auth", name: "Authfly sign in", docs: "Sign in with a password (email or username) or with a magic link; social providers are an extension point.",
  organism: "AuthflySignIn", axes: ["method", "identifier", "social"], fit: "card", data: [providers],
  variants: [
    ["password", "Email or username and password"],
    ["email", "Email and password", { identifier: "email" }],
    ["username", "Username and password", { identifier: "username" }],
    ["magic", "Magic link", { method: "magic", identifier: "email" }, { ...page("magic"), labels: k("magic.labels") }],
    ["social", "With social providers (stub)", { social: "show" }],
    ["error", "Wrong password, with providers", { identifier: "email", social: "show" }, { error: k("errors.credentials") }],
  ],
  facts: [{ sel: '[data-testid="authfly-sign-in"]', n: 1 }, { sel: '[data-testid="authfly-providers"]', n: 1, when: { social: "show" } }],
  sample: { id: "aksignin", ...page("signin"), action: "/auth/sign-in", csrf: "csrf-token", labels: k("signin.labels"), providers: ref("akproviders") },
});

const signup = define({
  key: "aksignup", theme: "account", group: "auth", name: "Authfly sign up", docs: "Create a Stalwart mailbox account: name, username at the domain, password.",
  organism: "AuthflySignUp", axes: ["terms"], fit: "card",
  variants: [["terms", "With terms"], ["taken", "Username taken, without terms", { terms: "none" }, { error: k("errors.taken") }]],
  facts: [{ sel: '[data-testid="authfly-sign-up"]', n: 1 }],
  sample: { id: "aksignup", ...page("signup"), action: "/auth/sign-up", csrf: "csrf-token", labels: k("signup.labels") },
});

const request = define({
  key: "akrequest", theme: "account", group: "auth", name: "Authfly request forms", docs: "Forgot password and magic-link request (one address), reset password (new password), one-time code (TOTP stub).",
  organism: "AuthflyRequest", axes: ["kind"], fit: "card",
  variants: [
    ["forgot", "Forgot password"],
    ["reset", "Reset password", { kind: "password" }, { ...page("reset"), labels: k("reset.labels"), action: "/auth/reset", token: "reset-token" }],
    ["code", "One-time code (TOTP stub)", { kind: "code" }, { ...page("code"), labels: k("code.labels"), action: "/auth/2fa" }],
  ],
  facts: [{ sel: '[data-testid="authfly-request"]', n: 1 }],
  sample: { id: "akrequest", ...page("forgot"), action: "/auth/forgot", csrf: "csrf-token", labels: k("forgot.labels") },
});

const notice = define({
  key: "aknotice", theme: "account", group: "auth", name: "Authfly notices", docs: "Check your email, link verified, email verified, signed out, sign out confirmation and errors.",
  organism: "AuthflyNotice", axes: ["tone", "action"], fit: "card",
  variants: [
    ["check", "Check your email"],
    ["verified", "Email verified", { tone: "success" }, { ...page("verified"), icon: "badge-check", labels: k("verified.labels"), detail: "" }],
    ["signout", "Sign out?", { action: "form" }, { ...page("signout"), icon: "log-out", labels: k("signout.labels"), detail: "", actionUrl: "/auth/sign-out" }],
    ["error", "Link invalid or expired", { tone: "error" }, { ...page("linkerror"), icon: "shield-alert", labels: k("linkerror.labels"), detail: "" }],
  ],
  facts: [{ sel: '[data-testid="authfly-notice"]', n: 1 }],
  sample: { id: "aknotice", ...page("check"), detail: "alice@example.com", icon: "mail-check", labels: k("check.labels"), csrf: "csrf-token" },
});

const consent = define({
  key: "akconsent", theme: "account", group: "auth", name: "Authfly consent", docs: "The OIDC handoff: an application asks to sign you in, allow or deny.",
  organism: "AuthflyConsent", axes: [], fit: "card", data: [scopes],
  variants: [["default", "Allow an application"]],
  facts: [{ sel: '[data-testid="authfly-consent"]', n: 1 }],
  sample: { id: "akconsent", ...page("consent"), action: "/oauth/consent", csrf: "csrf-token", client: "Demo app", account: "alice@example.com", scopes: ref("akscopes"), labels: k("consent.labels") },
});

const account = define({
  key: "akaccount", theme: "account", group: "settings", name: "Authfly account", docs: "Profile basics, sign-in methods and sign out.",
  organism: "AuthflyAccount", axes: [], fit: "card", data: [methods],
  variants: [["default", "Account"]],
  facts: [{ sel: '[data-testid="authfly-account"]', n: 1 }],
  sample: { id: "akaccount", ...page("account"), name: "Alice Example", email: "alice@example.com", verified: true, methods: ref("akmethods"), labels: k("account.labels"), signoutUrl: "/auth/sign-out", csrf: "csrf-token" },
});

export const authflyBlocks = [signin, signup, request, notice, consent, account];

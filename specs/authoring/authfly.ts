// Authfly organisms: the sign-in widgets of Authfly (self-hosted auth on Stalwart). Overlaid onto ui8kit/codegen at the pinned
// commit by tools/gen-ui.sh (copied to xgen/screens/src/authoring/blocks/authfly.ts), generated for all eight runtimes.
// Every widget is a real HTML form (method post) so it works without JavaScript in every runtime; the names of the controls
// are the Authfly form contract (docs/contract.md): identifier, password, email, name, username, token, code, csrf, return_to.
import { cn, cond, each, eq, organism, ref, text, tpl, use, when } from "../../build";
import type { OrganismSpec, ViewNode, Value } from "../../ir";
import { groupFields, rec, requireFields, spec } from "../kit";
import { id, tsOf } from "../props";
import { checkRow, fid, inputField, kids } from "../forms";
import { muted } from "../ux";

const O = "organism.";
/** inputField of ../forms with a computed input type (email or text by the identifier axis) */
const typedField = (name: string, type: Value, label: Value, auto: Value): ViewNode =>
  organism("Field", { label, htmlFor: fid(name) }, kids(use("Input", { props: { Type: type, Name: name, Autocomplete: auto }, attrs: { id: fid(name), "data-testid": "field" } })));
const panel = "mx-auto flex w-full max-w-sm flex-col gap-6 rounded bg-card p-6 inset-ring inset-ring-border";

/** the section and heading every widget shares */
const shell = (testid: string, ...body: ViewNode[]): ViewNode => shellOf(testid, true, ...body);
/** the shell; info false leaves out the status alert (the sign-in keeps its view within the size limit) */
const shellOf = (testid: string, info: boolean, ...body: ViewNode[]): ViewNode =>
  use("Block", { props: { Tag: "section", Class: panel }, attrs: { "aria-labelledby": tpl("{0}-title", ref("id")), "data-testid": testid } },
    use("Stack", { props: { Gap: "2", Align: "start" } },
      use("Title", { props: { As: 1, Size: "2xl", Weight: "bold" }, attrs: { id: tpl("{0}-title", ref("id")) } }, text(ref("title"))),
      muted(ref("text"))),
    when(ref("error"), [use("Alert", { props: { Variant: "destructive", Role: "alert" }, attrs: { "data-testid": "authfly-error" } },
      use("LucideIcon", { props: { Name: "circle-alert", Size: 16 } }), text(ref("error")))]),
    ...(info ? [when(ref("info"), [use("Alert", { props: { Variant: "success", Role: "status" }, attrs: { "data-testid": "authfly-info" } },
      use("LucideIcon", { props: { Name: "info", Size: 16 } }), text(ref("info")))])] : []),
    ...body);
const hidden = (name: string, v: Value): ViewNode => use("Input", { props: { Type: "hidden", Name: name, Value: v } });
const form = (testid: string, ...body: ViewNode[]): ViewNode =>
  use("Form", { props: { Method: "post", Action: ref("action") }, attrs: { "data-testid": testid } }, hidden("csrf", ref("csrf")), ...body);
/** one consent button: its own form with the hidden field decision */
const decide = (v: string, variant: string, label: Value): ViewNode =>
  use("Form", { props: { Method: "post", Action: ref("action"), Class: "flex-1" }, attrs: { "data-testid": v } }, hidden("csrf", ref("csrf")), hidden("decision", v),
    use("Button", { props: { Variant: variant, Size: "default", Type: "submit", Class: "w-full" } }, text(label)));
const submit = (v: Value): ViewNode => use("Button", { props: { Variant: "default", Size: "default", Type: "submit", Class: "w-full" }, attrs: { "data-testid": "submit" } }, text(v));
const footLink = (lead: Value, link: Value, href: Value, testid: string): ViewNode =>
  use("Text", { props: { Size: "sm", Class: "text-muted-foreground" } }, text(lead), text(" "),
    use("Link", { props: { Href: href, Variant: "default" }, attrs: { "data-testid": testid } }, text(link)));
const common = [
  id,
  { name: "title", type: "string" as const, required: true },
  { name: "text", type: "string" as const, required: true },
  { name: "action", type: "string" as const, required: true, docs: "the URL the form posts to" },
  { name: "csrf", type: "string" as const, default: "", docs: "anti-forgery token, sent back as the hidden field csrf" },
  { name: "error", type: "string" as const, default: "", docs: "an error message shown above the form (role alert)" },
  { name: "info", type: "string" as const, default: "", docs: "a status message shown above the form (role status)" },
];

const SignInLabels = requireFields(groupFields(
  ["identifier", "string", "label of the identifier field"], ["password", "string"], ["submit", "string"], ["forgot", "string"], ["forgotHref", "string"],
  ["magic", "string", "the way to the magic-link page"], ["magicHref", "string"], ["signupText", "string"], ["signupLink", "string"], ["signupHref", "string"],
  ["providers", "string", "accessible name of the social provider list (extension point)"], ["socialUrl", "string", "base URL of the social login routes"]), "identifier", "password", "submit");
const featureType = [{ from: "FeatureGrid", names: ["Feature"] }];

const signIn = spec(`${O}authfly-sign-in`, "AuthflySignIn", "Authfly sign-in. Axes: method (password: identifier and password, magic: identifier only, the server emails a link), identifier (email, username, any: what the identifier field accepts), social (none, show: provider buttons, an extension point).", {
  records: { SignInLabels }, typeImports: featureType,
  props: [...common.filter((p) => p.name !== "info"),
    { name: "labels", type: rec("SignInLabels"), required: true },
    { name: "providers", type: { ts: "Feature[]" }, required: true, docs: "social providers (stub): id, title, icon; the button goes to socialUrl/<id>" },
    { name: "method", type: tsOf("password", "magic"), default: "password" },
    { name: "identifier", type: tsOf("any", "email", "username"), default: "any" },
    { name: "social", type: tsOf("none", "show"), default: "none" },
  ],
  view: [shellOf("authfly-sign-in", false,
    when(eq(ref("social"), "show"), [use("Stack", { props: { Gap: "2", Align: "stretch" }, attrs: { role: "group", "aria-label": ref("labels.providers"), "data-testid": "authfly-providers" } },
      each(ref("providers"), "p", ref("p.id"), use("Button", { props: { Variant: "outline", Size: "default", Href: tpl("{0}/{1}", ref("labels.socialUrl"), ref("p.id")), Class: "w-full" }, attrs: { "data-provider": ref("p.id") } },
        use("LucideIcon", { props: { Name: ref("p.icon"), Size: 16 } }), text(ref("p.title")))))]),
    form("authfly-form",
      typedField("identifier", cond(eq(ref("identifier"), "email"), "email", "text"), ref("labels.identifier"), cond(eq(ref("identifier"), "email"), "email", "username")),
      when(eq(ref("method"), "password"), [inputField("password", "password", ref("labels.password"), "current-password"),
        use("Link", { props: { Href: ref("labels.forgotHref"), Variant: "default", Class: "w-fit text-sm" }, attrs: { "data-testid": "forgot" } }, text(ref("labels.forgot")))]),
      submit(ref("labels.submit"))),
    when(ref("labels.magic"), [use("Button", { props: { Variant: "outline", Size: "default", Href: ref("labels.magicHref"), Class: "w-full" }, attrs: { "data-testid": "switch-method" } },
      text(ref("labels.magic")))]),
    footLink(ref("labels.signupText"), ref("labels.signupLink"), ref("labels.signupHref"), "signup-link"))],
});

const SignUpLabels = requireFields(groupFields(
  ["name", "string"], ["username", "string"], ["domain", "string", "the mail domain shown after the username, e.g. @example.com"], ["password", "string"],
  ["hint", "string", "password rules"], ["terms", "string"], ["submit", "string"], ["signinText", "string"], ["signinLink", "string"], ["signinHref", "string"]),
  "name", "username", "domain", "password", "submit");
const signUp = spec(`${O}authfly-sign-up`, "AuthflySignUp", "Authfly sign-up: name, username at the mail domain, password, terms. The server creates the Stalwart account and sends the verification email. Axes: terms (show, none).", {
  records: { SignUpLabels },
  props: [...common, { name: "labels", type: rec("SignUpLabels"), required: true }, { name: "terms", type: tsOf("show", "none"), default: "show" }],
  view: [shell("authfly-sign-up",
    form("authfly-form",
      inputField("name", "text", ref("labels.name"), "name"),
      use("Stack", { props: { Gap: "2", Align: "stretch" } },
        use("Label", { props: { HTMLFor: tpl("{0}-username", ref("id")) } }, text(ref("labels.username"))),
        use("Group", { props: { Gap: "2", Align: "center" } },
          use("Input", { props: { Type: "text", Name: "username", Autocomplete: "username", Required: true }, attrs: { id: tpl("{0}-username", ref("id")), "data-testid": "field" } }),
          use("Inline", { props: { Class: "text-sm text-muted-foreground" }, attrs: { "data-testid": "domain" } }, text(ref("labels.domain"))))),
      inputField("password", "password", ref("labels.password"), "new-password"),
      when(ref("labels.hint"), [muted(ref("labels.hint"), "xs")]),
      when(eq(ref("terms"), "show"), [checkRow("terms", ref("labels.terms"))]),
      submit(ref("labels.submit"))),
    when(ref("labels.signinLink"), [footLink(ref("labels.signinText"), ref("labels.signinLink"), ref("labels.signinHref"), "signin-link")]))],
});

const RequestLabels = requireFields(groupFields(["field", "string", "label of the field"], ["confirm", "string", "label of the repeat field (kind password)"], ["submit", "string"], ["back", "string"], ["backHref", "string"]), "field", "confirm", "submit");
const request = spec(`${O}authfly-request`, "AuthflyRequest", "Authfly one-field forms. Axes: kind (email: magic-link request and forgot password, password: a new password and its repeat with the reset token, code: a one-time code, the TOTP extension point).", {
  records: { RequestLabels },
  props: [...common, { name: "labels", type: rec("RequestLabels"), required: true }, { name: "token", type: "string", default: "", docs: "the reset token, sent back as token" },
    { name: "kind", type: tsOf("email", "password", "code"), default: "email" }],
  view: [shell("authfly-request",
    form("authfly-form",
      when(eq(ref("kind"), "email"), [inputField("email", "text", ref("labels.field"), "email")]),
      when(eq(ref("kind"), "password"), [hidden("token", ref("token")), inputField("password", "password", ref("labels.field"), "new-password"), inputField("confirm", "password", ref("labels.confirm"), "new-password")]),
      when(eq(ref("kind"), "code"), [inputField("code", "text", ref("labels.field"), "one-time-code")]),
      submit(ref("labels.submit"))),
    when(ref("labels.back"), [use("Link", { props: { Href: ref("labels.backHref"), Variant: "default", Class: "w-fit text-sm" }, attrs: { "data-testid": "back" } }, text(ref("labels.back")))]))],
});

const NoticeLabels = requireFields(groupFields(["cta", "string", "the primary action"], ["ctaHref", "string", "its address; empty with action form: a submit button"], ["secondary", "string"], ["secondaryHref", "string"]), "cta");
const notice = spec(`${O}authfly-notice`, "AuthflyNotice", "Authfly result pages: check your email, link verified, email verified, signed out, sign out confirmation, errors. Axes: tone (default, success, error), action (link: the action is a link, form: a post form, used to sign out).", {
  records: { NoticeLabels },
  props: [id, { name: "title", type: "string", required: true }, { name: "text", type: "string", required: true },
    { name: "detail", type: "string", default: "", docs: "a highlighted value, e.g. the address the link went to" },
    { name: "icon", type: "string", default: "mail-check" }, { name: "labels", type: rec("NoticeLabels"), required: true },
    { name: "actionUrl", type: "string", default: "", docs: "the URL the form posts to (action form)" }, { name: "csrf", type: "string", default: "" },
    { name: "tone", type: tsOf("default", "success", "error"), default: "default" }, { name: "action", type: tsOf("link", "form"), default: "link" }],
  view: [use("Block", { props: { Tag: "section", Class: cn(panel, "items-center text-center") }, attrs: { "aria-labelledby": tpl("{0}-title", ref("id")), "data-testid": "authfly-notice", "data-tone": ref("tone") } },
    use("IconBadge", { props: { Variant: cond(eq(ref("tone"), "error"), "destructive", "default"), Size: "lg" } }, use("LucideIcon", { props: { Name: ref("icon"), Size: 24 } })),
    use("Stack", { props: { Gap: "2", Align: "center" } },
      use("Title", { props: { As: 1, Size: "2xl", Weight: "bold" }, attrs: { id: tpl("{0}-title", ref("id")), role: cond(eq(ref("tone"), "error"), "alert", "status") } }, text(ref("title"))),
      muted(ref("text")),
      when(ref("detail"), [use("Text", { props: { Size: "sm", Weight: "semibold" }, attrs: { "data-testid": "detail" } }, text(ref("detail")))])),
    when(eq(ref("action"), "form"),
      [use("Form", { props: { Method: "post", Action: ref("actionUrl"), Class: "w-full" }, attrs: { "data-testid": "authfly-form" } }, hidden("csrf", ref("csrf")), submit(ref("labels.cta")))],
      [use("Button", { props: { Variant: "default", Size: "default", Href: ref("labels.ctaHref"), Class: "w-full" }, attrs: { "data-testid": "cta" } }, text(ref("labels.cta")))]),
    when(ref("labels.secondary"), [use("Link", { props: { Href: ref("labels.secondaryHref"), Variant: "default", Class: "text-sm" }, attrs: { "data-testid": "secondary" } }, text(ref("labels.secondary")))]))],
});

const ConsentLabels = requireFields(groupFields(["account", "string", "the line before the account"], ["scopes", "string", "heading of the scope list"], ["approve", "string"], ["deny", "string"]), "account", "scopes", "approve", "deny");
const consent = spec(`${O}authfly-consent`, "AuthflyConsent", "Authfly OIDC handoff: the application asking, the signed-in account, the scopes, allow and deny (one form, the button sends decision=approve or deny).", {
  records: { ConsentLabels }, typeImports: featureType,
  props: [...common, { name: "client", type: "string", required: true, docs: "name of the application" }, { name: "account", type: "string", required: true },
    { name: "scopes", type: { ts: "Feature[]" }, required: true }, { name: "labels", type: rec("ConsentLabels"), required: true }],
  view: [shell("authfly-consent",
    use("Text", { props: { Size: "sm" }, attrs: { "data-testid": "account" } }, text(ref("labels.account")), text(" "), use("Inline", { props: { Class: "font-semibold" } }, text(ref("account")))),
    use("Stack", { props: { Gap: "2", Align: "stretch" } },
      use("Title", { props: { As: 2, Size: "sm", Weight: "semibold" } }, text(ref("labels.scopes"))),
      use("List", { props: { Class: "m-0 flex list-none flex-col gap-2 p-0" }, attrs: { "data-testid": "scopes" } },
        each(ref("scopes"), "s", ref("s.id"), use("ListItem", { props: { Class: "flex items-center gap-2 text-sm" } }, use("LucideIcon", { props: { Name: "check", Size: 16 } }), text(ref("s.title")))))),
    use("Group", { props: { Gap: "2", Justify: "between" } },
      decide("deny", "outline", ref("labels.deny")), decide("approve", "default", ref("labels.approve"))))],
});

const AccountLabels = requireFields(groupFields(["name", "string"], ["email", "string"], ["verified", "string"], ["unverified", "string"], ["security", "string"], ["signout", "string"]), "name", "email", "security", "signout");
const account = spec(`${O}authfly-account`, "AuthflyAccount", "Authfly account basics: name, address, verification, the sign-in methods (password, magic link; TOTP, security keys and social as extension points) and sign out.", {
  records: { AccountLabels }, typeImports: featureType,
  props: [id, { name: "title", type: "string", required: true }, { name: "text", type: "string", required: true },
    { name: "name", type: "string", required: true }, { name: "email", type: "string", required: true }, { name: "verified", type: "boolean", default: false },
    { name: "methods", type: { ts: "Feature[]" }, required: true }, { name: "labels", type: rec("AccountLabels"), required: true },
    { name: "signoutUrl", type: "string", required: true }, { name: "csrf", type: "string", default: "" }],
  view: [use("Block", { props: { Tag: "section", Class: cn(panel, "max-w-lg") }, attrs: { "aria-labelledby": tpl("{0}-title", ref("id")), "data-testid": "authfly-account" } },
    use("Stack", { props: { Gap: "2", Align: "start" } },
      use("Title", { props: { As: 1, Size: "2xl", Weight: "bold" }, attrs: { id: tpl("{0}-title", ref("id")) } }, text(ref("title"))), muted(ref("text"))),
    use("List", { props: { Tag: "dl", Class: "m-0 grid gap-4" }, attrs: { "data-testid": "profile" } },
      use("Box", { props: { Class: "grid gap-2" } },
        use("ListItem", { props: { Tag: "dt", Class: "text-sm text-muted-foreground" } }, text(ref("labels.name"))),
        use("ListItem", { props: { Tag: "dd", Class: "m-0 font-semibold" }, attrs: { "data-testid": "profile-name" } }, text(ref("name")))),
      use("Box", { props: { Class: "grid gap-2" } },
        use("ListItem", { props: { Tag: "dt", Class: "text-sm text-muted-foreground" } }, text(ref("labels.email"))),
        use("ListItem", { props: { Tag: "dd", Class: "m-0 flex flex-wrap items-center gap-2 font-semibold" }, attrs: { "data-testid": "profile-email" } }, text(ref("email")),
          use("Badge", { props: { Variant: cond(ref("verified"), "default", "secondary"), Size: "sm" }, attrs: { "data-testid": "verified" } }, text(cond(ref("verified"), ref("labels.verified"), ref("labels.unverified"))))))),
    use("Separator", { props: { Decorative: true } }),
    use("Stack", { props: { Gap: "2", Align: "stretch" } },
      use("Title", { props: { As: 2, Size: "sm", Weight: "semibold" } }, text(ref("labels.security"))),
      use("List", { props: { Class: "m-0 flex list-none flex-col gap-2 p-0" }, attrs: { "data-testid": "methods" } },
        each(ref("methods"), "m", ref("m.id"), use("ListItem", { props: { Class: "flex items-center justify-between gap-4 text-sm" }, attrs: { "data-method": ref("m.id") } },
          use("Inline", { props: { Class: "flex items-center gap-2" } }, use("LucideIcon", { props: { Name: cond(ref("m.icon"), ref("m.icon"), "shield"), Size: 16 } }), text(ref("m.title"))),
          use("Badge", { props: { Variant: "outline", Size: "sm" } }, text(ref("m.text"))))))),
    use("Form", { props: { Method: "post", Action: ref("signoutUrl") }, attrs: { "data-testid": "signout-form" } }, hidden("csrf", ref("csrf")),
      use("Button", { props: { Variant: "outline", Size: "default", Type: "submit", Class: "w-full" }, attrs: { "data-testid": "signout" } }, use("LucideIcon", { props: { Name: "log-out", Size: 16 } }), text(ref("labels.signout")))))],
});

export const authflyOrganisms: OrganismSpec[] = [signIn, signUp, request, notice, consent, account];

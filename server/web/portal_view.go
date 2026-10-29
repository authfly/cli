package web

import (
	"time"

	"github.com/a-h/templ"
	af "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/authkit/packages/ui/templ/ui/box"
	"github.com/authfly/authkit/packages/ui/templ/ui/button"
	"github.com/authfly/authkit/packages/ui/templ/ui/checkbox"
	"github.com/authfly/authkit/packages/ui/templ/ui/input"
	"github.com/authfly/authkit/packages/ui/templ/ui/label"
	"github.com/authfly/authkit/packages/ui/templ/ui/link"
	"github.com/authfly/authkit/packages/ui/templ/ui/text"
	"github.com/authfly/cli/server/core"
)

func fieldFn(f func(af.FieldControl) templ.Component) func(af.FieldControl) templ.Component {
	return f
}

func labStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func sectionTitle(id, title, lead string) templ.Component {
	return nest(af.Stack("2", "start", "", "", nil), many(
		af.Title(1, id+"-title", "", title),
		nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(lead)),
	))
}

func flash(msg string) templ.Component {
	if msg == "" {
		return nil
	}
	return af.Alert("success", "circle-check", "", "authfly-info", msg)
}

func formErr(msg string) templ.Component {
	if msg == "" {
		return nil
	}
	return af.Alert("destructive", "circle-alert", "authfly-error", "authfly-error", msg)
}

func submitBtn(testid, label string) templ.Component {
	return nest(button.Button(button.ButtonProps{Type: "submit", Class: af.ButtonSkin("default"), Attrs: af.A("data-testid", testid)}), textNode(label))
}

func outlineSubmit(testid, label string) templ.Component {
	return nest(button.Button(button.ButtonProps{Type: "submit", Class: af.ButtonSkin("outline"), Attrs: af.A("data-testid", testid)}), textNode(label))
}

func textField(id, name, typ, autocomplete, value string, required bool, lbl string) templ.Component {
	return af.Field(af.FieldProps{Label: lbl, HtmlFor: id}, fieldFn(func(f af.FieldControl) templ.Component {
		p := input.InputProps{Type: typ, Name: name, ID: id, Required: required, Class: af.InputSkin(),
			AriaDescribedBy: f.Describe(), AriaInvalid: f.Invalid, Attrs: af.A("autocomplete", autocomplete, "data-testid", "field")}
		if value != "" {
			v := value
			p.Value = &v
		}
		return input.Input(p)
	}))
}

func usernameField(id, domain, lbl string) templ.Component {
	return af.Field(af.FieldProps{Label: lbl, HtmlFor: id + "-username"}, fieldFn(func(f af.FieldControl) templ.Component {
		row := []templ.Component{af.TextInput(f, "text", "username", "username", id+"-username", true, "")}
		if domain != "" {
			row = append(row, nest(text.Text(text.TextProps{Tag: "span", Class: af.TextMuted, Attrs: af.A("id", id+"-domain", "data-testid", "domain")}), textNode(domain)))
		}
		return nest(af.Group("2", "", "", "", nil), many(row...))
	}))
}

// InviteGate asks for the invite code before the sign-up form.
func InviteGate(title, lead, action, csrf, errMsg string, labels map[string]any) templ.Component {
	return nest(af.Card("", af.A("data-testid", "authfly-invite")), many(
		af.WidgetHead("invite", title, lead, "", ""),
		formErr(errMsg),
		nest(af.Form(action, "", af.A("data-testid", "authfly-form")), many(
			af.Hidden("csrf", csrf),
			textField("invite-token", "invite", "text", "off", "", true, labStr(labels, "token")),
			submitBtn("submit", labStr(labels, "submit")),
		)),
		nest(text.Text(text.TextProps{Class: af.TextMuted}), many(
			textNode(labStr(labels, "signinText")+" "),
			nest(link.Link(link.LinkProps{Href: labStr(labels, "signinHref"), Class: af.LinkSkin(), Attrs: af.A("data-testid", "signin-link")}), textNode(labStr(labels, "signinLink"))),
		)),
	))
}

// SignUpWithInvite is AuthflySignUp plus the invite field (authkit widget has no extra slot).
func SignUpWithInvite(title, lead, action, csrf, errMsg, invite, domain string, labels map[string]any) templ.Component {
	terms := nest(af.Group("2", "", "", "w-fit", nil), many(
		checkbox.Checkbox(checkbox.CheckboxProps{Name: "terms", Required: true, ID: "authfly-terms", Class: af.CheckboxSkin()}),
		nest(label.Label(label.LabelProps{For: "authfly-terms", Class: af.LabelSkin("font-normal")}), textNode(labStr(labels, "terms"))),
	))
	inviteField := textField("authfly-invite", "invite", "text", "off", invite, true, labStr(labels, "invite"))
	if invite != "" {
		inviteField = af.Hidden("invite", invite)
	}
	return nest(af.Card("", af.A("data-testid", "authfly-sign-up")), many(
		af.WidgetHead("authfly", title, lead, "", ""),
		formErr(errMsg),
		nest(af.Form(action, "", af.A("data-testid", "authfly-form")), many(
			af.Hidden("csrf", csrf),
			inviteField,
			textField("authfly-name", "name", "text", "name", "", false, labStr(labels, "name")),
			usernameField("authfly", domain, labStr(labels, "username")),
			af.Field(af.FieldProps{Label: labStr(labels, "password"), HtmlFor: "authfly-password", Hint: labStr(labels, "hint")}, fieldFn(func(f af.FieldControl) templ.Component {
				return af.TextInput(f, "password", "password", "new-password", "authfly-password", true, "")
			})),
			terms,
			submitBtn("submit", labStr(labels, "submit")),
		)),
		nest(text.Text(text.TextProps{Class: af.TextMuted}), many(
			textNode(labStr(labels, "signinText")+" "),
			nest(link.Link(link.LinkProps{Href: labStr(labels, "signinHref"), Class: af.LinkSkin(), Attrs: af.A("data-testid", "signin-link")}), textNode(labStr(labels, "signinLink"))),
		)),
	))
}

func portalStack(children ...templ.Component) templ.Component {
	return nest(af.Stack("8", "start", "", "w-full max-w-3xl", af.A("data-testid", "portal")), many(children...))
}

// HomeTile is one dashboard card on the cabinet home.
type HomeTile struct{ Href, Icon, Title, Lead string }

func PortalHome(title, lead, name, email string, tiles []HomeTile) templ.Component {
	items := make([]templ.Component, 0, len(tiles))
	for _, t := range tiles {
		items = append(items, tile(t.Href, t.Icon, t.Title, t.Lead))
	}
	return portalStack(
		sectionTitle("home", title+", "+name, lead),
		nest(af.Group("2", "center", "", "text-sm text-muted-foreground", af.A("data-testid", "home-email")), many(af.LucideIcon("mail", "sm"), textNode(email))),
		grid(items...),
	)
}

func PortalPersonal(title, lead, csrf, name, email, username, kind, info, errMsg string, labels map[string]any) templ.Component {
	return portalStack(
		sectionTitle("personal", title, lead),
		flash(info),
		formErr(errMsg),
		section("personal-name-card", "personal-profile", "circle-user", labStr(labels, "name"), "",
			nest(af.Form("/account/personal", "", af.A("data-testid", "personal-form")), many(
				af.Hidden("csrf", csrf),
				textField("personal-name", "name", "text", "name", name, false, labStr(labels, "name")),
				nest(box.Box(box.BoxProps{Class: "flex"}), submitBtn("save", labStr(labels, "save"))),
			)),
		),
		section("personal-account", "personal-ids", "id-card", labStr(labels, "email"), "",
			nest(box.Box(box.BoxProps{Tag: "dl", Class: "m-0 grid gap-4 sm:grid-cols-3"}), many(
				kv(labStr(labels, "email"), email),
				kv(labStr(labels, "username"), username),
				kv(labStr(labels, "kind"), kind),
			)),
		),
	)
}

func kv(k, v string) templ.Component {
	return nest(box.Box(box.BoxProps{Class: "grid min-w-0 gap-2"}), many(
		nest(box.Box(box.BoxProps{Tag: "dt", Class: af.TextMuted}), textNode(k)),
		nest(box.Box(box.BoxProps{Tag: "dd", Class: "m-0 font-semibold text-foreground"}), textNode(v)),
	))
}

func PortalSecurity(title, lead, csrf, info, errMsg, otpauth string, totpOn bool, apps []core.AppPassword, sessions []core.SessionRec, thisSID string, labels map[string]any) templ.Component {
	totpState, totpTone := labStr(labels, "totpOff"), "secondary"
	if totpOn {
		totpState, totpTone = labStr(labels, "totpOn"), "default"
	}
	var otp templ.Component
	if otpauth != "" {
		v := otpauth
		otp = af.Field(af.FieldProps{Label: labStr(labels, "totpSecret"), HtmlFor: "sec-otpauth"}, fieldFn(func(f af.FieldControl) templ.Component {
			return input.Input(input.InputProps{Type: "text", ID: "sec-otpauth", Value: &v, Class: af.InputSkin(), AriaDescribedBy: f.Describe(), Attrs: af.A("readonly", "readonly", "data-testid", "otpauth")})
		}))
	}
	totpForm := nest(af.Form("/account/security/totp", "max-w-sm", nil), many(
		af.Hidden("csrf", csrf),
		textField("sec-pw-totp", "password", "password", "current-password", "", true, labStr(labels, "current")),
		textField("sec-code", "code", "text", "one-time-code", "", totpOn, labStr(labels, "code")),
		af.Hidden("op", map[bool]string{true: "disable", false: "enable"}[totpOn]),
		nest(box.Box(box.BoxProps{Class: "flex"}), submitBtn("totp", map[bool]string{true: labStr(labels, "totpDisable"), false: labStr(labels, "totpEnable")}[totpOn])),
	))
	appRows := make([]templ.Component, 0, len(apps)+1)
	for _, a := range apps {
		id := a.ID
		appRows = append(appRows, nest(af.Group("4", "center", "between", "w-full flex-wrap", af.A("data-testid", "app-password")), many(
			nest(af.Group("2", "center", "", "", nil), many(af.LucideIcon("key-round", "sm"), nest(text.Text(text.TextProps{Class: "text-sm font-semibold"}), textNode(nonEmpty(a.Description, id))))),
			confirm(labStr(labels, "revoke"), labStr(labels, "revokeQ"), true, nest(af.Form("/account/security/apps/revoke", "", nil), many(
				af.Hidden("csrf", csrf), af.Hidden("id", id),
				dangerSubmit("revoke-app", labStr(labels, "revoke")),
			))),
		)))
	}
	if len(apps) == 0 {
		appRows = append(appRows, empty("key-round", labStr(labels, "appsEmpty")))
	}
	sessRows := make([]templ.Component, 0, len(sessions))
	for _, rec := range sessions {
		tag := rec.UserAgent
		if rec.ID == thisSID {
			tag = labStr(labels, "thisDevice")
		}
		when := time.Unix(rec.Created, 0).UTC().Format("2006-01-02 15:04 UTC")
		sessRows = append(sessRows, nest(af.Group("2", "center", "", "text-sm text-muted-foreground", nil), many(af.LucideIcon("monitor", "sm"), textNode(when+" · "+tag))))
	}
	return portalStack(
		sectionTitle("security", title, lead),
		flash(info),
		formErr(errMsg),
		section("password", "sec-password", "lock-keyhole", labStr(labels, "password"), "",
			nest(af.Form("/account/security/password", "max-w-sm", nil), many(
				af.Hidden("csrf", csrf),
				textField("sec-current", "current", "password", "current-password", "", true, labStr(labels, "current")),
				textField("sec-next", "next", "password", "new-password", "", true, labStr(labels, "next")),
				textField("sec-confirm", "confirm", "password", "new-password", "", true, labStr(labels, "confirm")),
				nest(box.Box(box.BoxProps{Class: "flex"}), submitBtn("change-password", labStr(labels, "change"))),
			)),
		),
		section("totp", "sec-totp", "shield-check", labStr(labels, "totp"), labStr(labels, "totpHint"),
			nest(af.Group("2", "center", "", "", nil), many(nest(text.Text(text.TextProps{Tag: "span", Class: af.TextMuted}), textNode(labStr(labels, "status"))), af.Badge(totpTone, "totp-state", totpState))),
			otp,
			totpForm,
		),
		section("app-passwords", "sec-apps", "key-round", labStr(labels, "apps"), labStr(labels, "appsHint"),
			nest(af.Stack("4", "", "", "w-full", nil), many(appRows...)),
			nest(af.Form("/account/security/apps", "max-w-sm", nil), many(
				af.Hidden("csrf", csrf),
				textField("app-name", "label", "text", "off", "", true, labStr(labels, "appName")),
				nest(box.Box(box.BoxProps{Class: "flex"}), outlineSubmit("create-app", labStr(labels, "appCreate"))),
			)),
		),
		section("sessions", "sec-sessions", "monitor-smartphone", labStr(labels, "sessions"), "",
			nest(af.Stack("2", "", "", "", nil), many(sessRows...)),
			confirm(labStr(labels, "everywhere"), labStr(labels, "everywhereQ"), true, nest(af.Form("/account/security/everywhere", "", nil), many(
				af.Hidden("csrf", csrf),
				dangerSubmit("everywhere", labStr(labels, "everywhere")),
			))),
		),
	)
}

func PortalApps(title, lead, csrf, info, empty string, grants []core.OAuthGrant, revokeLabel string) templ.Component {
	rows := make([]templ.Component, 0, len(grants))
	for _, g := range grants {
		name := nonEmpty(g.ClientName, g.ClientID)
		scopes := ""
		for k := range g.Scopes {
			if scopes != "" {
				scopes += ", "
			}
			scopes += k
		}
		rows = append(rows, nest(box.Box(box.BoxProps{Class: "flex flex-wrap items-center justify-between gap-4"}), many(
			nest(af.Stack("2", "start", "", "min-w-0", nil), many(
				nest(text.Text(text.TextProps{Class: "font-semibold"}), textNode(name)),
				nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(scopes)),
				nest(text.Text(text.TextProps{Class: af.TextHint}), textNode(g.LastUsedAt)),
			)),
			nest(af.Form("/account/apps/revoke", "", nil), many(
				af.Hidden("csrf", csrf), af.Hidden("id", g.ID),
				outlineSubmit("revoke-grant", revokeLabel),
			)),
		)))
	}
	body := many(rows...)
	if len(grants) == 0 {
		body = nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(empty))
	}
	return portalStack(sectionTitle("apps", title, lead), flash(info), body)
}

func PortalPrivacy(title, lead, csrf, info, errMsg string, events []core.AuditEvent, labels map[string]any) templ.Component {
	ev := make([]templ.Component, 0, len(events))
	for _, e := range events {
		line := e.Time + " · " + e.Action + " · " + e.Outcome
		ev = append(ev, nest(af.Group("2", "center", "", "text-sm text-muted-foreground", nil), many(af.LucideIcon("activity", "sm"), textNode(line))))
	}
	if len(events) == 0 {
		ev = append(ev, empty("activity", labStr(labels, "auditEmpty")))
	}
	return portalStack(
		sectionTitle("privacy", title, lead),
		flash(info),
		formErr(errMsg),
		section("export", "privacy-export", "download", labStr(labels, "export"), labStr(labels, "exportHint"),
			nest(box.Box(box.BoxProps{Class: "flex"}), nest(button.Button(button.ButtonProps{Href: "/account/privacy/export", Class: af.ButtonSkin("outline"), Attrs: af.A("data-testid", "export")}), many(af.LucideIcon("download", "sm"), textNode(labStr(labels, "export"))))),
		),
		section("audit-log", "audit", "activity", labStr(labels, "audit"), "",
			nest(af.Stack("2", "", "", "", nil), many(ev...)),
		),
		dangerSection("danger", "delete", labStr(labels, "delete"), labStr(labels, "deleteHint"),
			confirm(labStr(labels, "confirm"), labStr(labels, "deleteQ"), true, nest(af.Form("/account/privacy/erase", "", af.A("data-testid", "erase-form")), many(
				af.Hidden("csrf", csrf),
				textField("erase-pw", "password", "password", "current-password", "", true, labStr(labels, "password")),
				dangerSubmit("erase", labStr(labels, "confirm")),
			))),
		),
	)
}


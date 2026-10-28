package web

import (
	"github.com/a-h/templ"
	"github.com/authfly/cli/server/ext"
	blocks "github.com/authfly/authkit/packages/ui/templ/authfly"
)

// Preview is one widget state rendered with the hosted pages' labels, for the docs site's live previews.
type Preview struct {
	Slug, Name, Note string
	Widget           templ.Component
}

// Previews renders every Authfly widget state the hosted pages use, with sample data and no live service.
func (s *Server) Previews() []Preview {
	const csrf = "preview"
	notice := func(page, tone, icon, detail string, override map[string]any) templ.Component {
		l := s.labLang("en", page)
		for k, v := range override {
			l[k] = v
		}
		return blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "preview-" + page, Title: s.textLang("en", page, "title"), Text: s.textLang("en", page, "text"),
			Detail: detail, Icon: icon, Labels: l, Tone: tone, Action: "link"})
	}
	signIn := func(id, page, method, ident, social, err string) templ.Component {
		return blocks.AuthflySignIn(blocks.AuthflySignInProps{Id: id, Title: s.textLang("en", page, "title"), Text: s.textLang("en", page, "text"), Action: "#",
			Csrf: csrf, Error: err, Labels: s.labLang("en", page), Providers: s.providers(), Method: method, Identifier: ident, Social: social})
	}
	request := func(page, kind, token string) templ.Component {
		return blocks.AuthflyRequest(blocks.AuthflyRequestProps{Id: "preview-" + page, Title: s.textLang("en", page, "title"), Text: s.textLang("en", page, "text"),
			Action: "#", Csrf: csrf, Labels: s.labLang("en", page), Token: token, Kind: kind})
	}
	scopes := []map[string]any{
		{"id": "openid", "title": "Your account identifier", "text": "openid", "icon": "check"},
		{"id": "email", "title": "Your email address", "text": "email", "icon": "check"},
		{"id": "profile", "title": "Your name", "text": "profile", "icon": "check"},
	}
	errs := s.textLang("en", "errors", "credentials")
	return []Preview{
		{"sign-in", "Sign in (password)", "Username or email address plus password. Method password, identifier any.", signIn("preview-signin", "signin", "password", "any", "none", "")},
		{"sign-in-error", "Sign in (error state)", "Wrong credentials: the alert is the error slot of every form widget.", signIn("preview-signin-error", "signin", "password", "any", "none", errs)},
		{"sign-in-social", "Sign in with social stubs", "Extension stubs on (AUTHFLY_SOCIAL_STUBS): provider buttons render, the routes answer 501.", signIn("preview-signin-social", "signin", "password", "email", "show", "")},
		{"magic", "Magic link request", "Email only; the link signs you in to Authfly.", signIn("preview-magic", "magic", "magic", "email", "none", "")},
		{"sign-up", "Sign up", "Creates the mailbox account in Stalwart: name, username at your domain, password, terms.", blocks.AuthflySignUp(blocks.AuthflySignUpProps{Id: "preview-signup", Title: s.textLang("en", "signup", "title"), Text: s.textLang("en", "signup", "text"), Action: "#", Csrf: csrf, Labels: s.labLang("en", "signup"), Terms: "show"})},
		{"check-email", "Check your email", "After sign up, a magic link request or a reset request.", notice("check", "default", "mail-check", "alice@example.com", nil)},
		{"verified", "Email verified / magic link verified", "The verification link landed.", notice("verified", "success", "badge-check", "alice@example.com", nil)},
		{"forgot", "Forgot password", "Asks for the address the reset link goes to.", request("forgot", "email", "")},
		{"reset", "Reset password", "New password and confirmation; the token rides in a hidden field.", request("reset", "password", "token")},
		{"code", "Verification code", "Code entry (kind code), for second factors once an extension is wired.", request("code", "code", "")},
		{"link-error", "Link expired or used", "Error page for expired, used or forged links and failed handoffs.", notice("linkerror", "error", "shield-alert", "", nil)},
		{"sign-out", "Sign out", "Confirms with a POST (CSRF protected).", blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "preview-signout", Title: s.textLang("en", "signout", "title"), Text: s.textLang("en", "signout", "text"), Icon: "log-out", Labels: s.labLang("en", "signout"), Tone: "default", Action: "form", ActionUrl: "#", Csrf: csrf})},
		{"account", "Account", "Profile, verified badge, sign-in methods (TOTP and WebAuthn shown as stubs) and sign out.", blocks.AuthflyAccount(blocks.AuthflyAccountProps{Id: "preview-account", Title: s.textLang("en", "account", "title"), Text: "Signed in with a password.", Name: "Alice Example", Email: "alice@example.com", Verified: true, Methods: Methods(ext.Registry{TOTP: ext.StubTOTP{}, WebAuthn: ext.StubWebAuthn{}}), Labels: s.labLang("en", "account"), SignoutUrl: "#", Csrf: csrf})},
		{"consent", "OIDC consent handoff", "An application asks to sign you in through Stalwart's OpenID provider; allow or deny.", blocks.AuthflyConsent(blocks.AuthflyConsentProps{Id: "preview-consent", Title: s.textLang("en", "consent", "title"), Text: "Demo app wants to sign you in with your mail account.", Action: "#", Csrf: csrf, Client: "Demo app", Account: "alice@example.com", Scopes: scopes, Labels: s.labLang("en", "consent")})},
	}
}

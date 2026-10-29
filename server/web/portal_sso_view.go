package web

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	af "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/authkit/packages/ui/templ/ui/box"
	"github.com/authfly/authkit/packages/ui/templ/ui/button"
	"github.com/authfly/authkit/packages/ui/templ/ui/text"
	"github.com/authfly/cli/server/idp"
)

// SSOApp is one row of the "Apps" cabinet page.
type SSOApp struct {
	ClientID, Name, Scopes, First, Last string
	Sessions                            int // live SSO sessions in which the app is signed in (0 = signed out)
}

// SSOSession is one row of the active-sessions list.
type SSOSession struct {
	SID, Device, IP, Created, LastSeen, Apps string
	Current                                  bool
}

func when(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(time.UTC).Format("2006-01-02 15:04 UTC")
}

func (s *Server) ssoRows(sub, current string) ([]SSOApp, []SSOSession) {
	name := func(id string) string {
		if c := s.IdP.Clients[id]; c != nil && c.Name != "" {
			return c.Name
		}
		return id
	}
	var apps []SSOApp
	live := map[string]int{}
	for _, ss := range s.IdP.Store.SessionsOf(sub) {
		if !s.Svc.Store.HasSession(ss.Account, ss.SID) {
			continue
		}
		for cid := range ss.Clients {
			live[cid]++
		}
	}
	for _, g := range s.IdP.Store.GrantsOf(sub) {
		apps = append(apps, SSOApp{ClientID: g.ClientID, Name: name(g.ClientID), Scopes: strings.Join(g.Scopes, " "), First: when(g.First), Last: when(g.Last), Sessions: live[g.ClientID]})
	}
	var sess []SSOSession
	for _, ss := range s.IdP.Store.SessionsOf(sub) {
		if !s.Svc.Store.HasSession(ss.Account, ss.SID) {
			continue
		}
		var names []string
		for cid := range ss.Clients {
			names = append(names, name(cid))
		}
		sort.Strings(names)
		sess = append(sess, SSOSession{SID: ss.SID, Device: deviceName(ss.UserAgent), IP: ss.IP, Created: when(ss.Created), LastSeen: when(ss.LastSeen),
			Apps: strings.Join(names, ", "), Current: ss.SID == current})
	}
	return apps, sess
}

func deviceName(ua string) string {
	if ua == "" {
		return "Unknown device"
	}
	if len(ua) > 96 {
		return ua[:96] + "…"
	}
	return ua
}

// action is a CSRF-protected one-button form with a muted helper line under it (8px gap). Danger actions sit behind
// a confirm disclosure (question + the real submit).
func action(path, csrf, client, testid, label, hint, variant, hintID string, question ...string) templ.Component {
	form := func(cls string) templ.Component {
		return nest(af.Form(path, "", nil), many(
			af.Hidden("csrf", csrf), af.Hidden("client", client),
			nest(button.Button(button.ButtonProps{Type: "submit", Class: cls, Attrs: af.A("data-testid", testid)}), textNode(label)),
		))
	}
	var ctl templ.Component
	if variant == "danger" && len(question) > 0 {
		ctl = confirm(label, question[0], true, form(dangerSkin()))
	} else {
		ctl = form(af.ButtonSkin("outline"))
	}
	return nest(af.Stack("2", "end", "", "max-w-sm", nil), many(
		ctl,
		nest(text.Text(text.TextProps{Class: af.TextHint + " text-right", Attrs: af.A("data-testid", hintID)}), textNode(hint)),
	))
}

func muted(s string) templ.Component {
	return nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(s))
}

func row(left, right templ.Component, testid string) templ.Component {
	return nest(box.Box(box.BoxProps{Class: "flex w-full flex-wrap items-center justify-between gap-4", Attrs: af.A("data-testid", testid)}), many(
		nest(af.Stack("2", "start", "", "min-w-0", nil), left), right))
}

// PortalSSO renders Apps / Приложения: signed-in apps (revoke one) and sessions (end one, others, everywhere).
func PortalSSO(title, lead, csrf, info string, labels map[string]any, apps []SSOApp, sessions []SSOSession) templ.Component {
	appRows := make([]templ.Component, 0, len(apps))
	for _, a := range apps {
		status, tone := labStr(labels, "signedOut"), "bg-muted text-muted-foreground"
		if a.Sessions == 1 {
			status, tone = labStr(labels, "signedIn"), "bg-primary text-primary-foreground"
		} else if a.Sessions > 1 {
			status, tone = strings.ReplaceAll(labStr(labels, "signedInN"), "{n}", strconv.Itoa(a.Sessions)), "bg-primary text-primary-foreground"
		}
		state := map[bool]string{true: "signed-in", false: "signed-out"}[a.Sessions > 0]
		actions := []templ.Component{}
		if a.Sessions > 0 {
			actions = append(actions, action("/account/apps/client/sign-out", csrf, a.ClientID, "sign-out-"+a.ClientID, labStr(labels, "signOut"), labStr(labels, "signOutHint"), "outline", "sign-out-hint"))
		}
		actions = append(actions, action("/account/apps/client/revoke", csrf, a.ClientID, "revoke-"+a.ClientID, labStr(labels, "revoke"), labStr(labels, "revokeHint"), "danger", "revoke-hint", labStr(labels, "revokeQ")))
		appRows = append(appRows, row(many(
			nest(box.Box(box.BoxProps{Class: "flex flex-wrap items-center gap-2"}), many(
				nest(text.Text(text.TextProps{Class: "font-semibold"}), textNode(a.Name)),
				nest(text.Text(text.TextProps{Tag: "span", Class: "inline-flex items-center h-6 rounded-full px-2 text-xs font-medium " + tone, Attrs: af.A("data-testid", "status-"+a.ClientID, "data-state", state)}), textNode(status)),
			)),
			muted(labStr(labels, "scopes")+": "+a.Scopes),
			nest(text.Text(text.TextProps{Class: af.TextHint}), textNode(labStr(labels, "first")+" "+a.First+" · "+labStr(labels, "last")+" "+a.Last)),
		), nest(box.Box(box.BoxProps{Class: "flex flex-wrap items-start justify-end gap-4"}), many(actions...)), "app-"+a.ClientID))
	}
	if len(apps) == 0 {
		appRows = append(appRows, empty("layout-grid", labStr(labels, "empty")))
	}
	sessRows := make([]templ.Component, 0, len(sessions))
	for _, ss := range sessions {
		head := ss.Device
		if ss.Current {
			head = labStr(labels, "current") + " · " + head
		}
		meta := labStr(labels, "ip") + " " + ss.IP + " · " + labStr(labels, "created") + " " + ss.Created + " · " + labStr(labels, "lastSeen") + " " + ss.LastSeen
		left := many(
			nest(text.Text(text.TextProps{Class: "font-semibold truncate"}), textNode(head)),
			nest(text.Text(text.TextProps{Class: af.TextHint}), textNode(meta)),
		)
		if ss.Apps != "" {
			left = many(left, muted(labStr(labels, "appsIn")+": "+ss.Apps))
		}
		tid := "session"
		if ss.Current {
			tid = "session-current"
		}
		sessRows = append(sessRows, row(left, nest(af.Form("/account/sessions/revoke", "", nil), many(
			af.Hidden("csrf", csrf), af.Hidden("sid", ss.SID),
			outlineSubmit("end-session", labStr(labels, "end")),
		)), tid))
	}
	if len(sessions) == 0 {
		sessRows = append(sessRows, empty("monitor", labStr(labels, "noSessions")))
	}
	return portalStack(
		sectionTitle("apps", title, lead),
		flash(info),
		section("sso-apps", "apps-signed-in", "layout-grid", labStr(labels, "appsTitle"), "",
			nest(af.Stack("4", "start", "", "w-full", nil), many(appRows...)),
		),
		section("sso-sessions", "apps-sessions", "monitor-smartphone", labStr(labels, "sessionsTitle"), "",
			nest(af.Stack("4", "start", "", "w-full", nil), many(sessRows...)),
			nest(box.Box(box.BoxProps{Class: "flex flex-wrap items-start gap-4"}), many(
				confirm(labStr(labels, "others"), labStr(labels, "othersQ"), false, nest(af.Form("/account/sessions/others", "", nil), many(af.Hidden("csrf", csrf), outlineSubmit("sign-out-others", labStr(labels, "others"))))),
				confirm(labStr(labels, "everywhere"), labStr(labels, "everywhereQ"), true, nest(af.Form("/account/sessions/everywhere", "", nil), many(af.Hidden("csrf", csrf), dangerSubmit("sign-out-everywhere", labStr(labels, "everywhere"))))),
			)),
		),
	)
}

var _ = idp.PathLogin

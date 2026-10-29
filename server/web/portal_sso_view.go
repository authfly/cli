package web

import (
	"sort"
	"strings"
	"time"

	"github.com/a-h/templ"
	af "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/authkit/packages/ui/templ/ui/box"
	"github.com/authfly/authkit/packages/ui/templ/ui/text"
	"github.com/authfly/cli/server/idp"
)

// SSOApp is one row of the "Apps" cabinet page.
type SSOApp struct {
	ClientID, Name, Scopes, First, Last string
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
	for _, g := range s.IdP.Store.GrantsOf(sub) {
		apps = append(apps, SSOApp{ClientID: g.ClientID, Name: name(g.ClientID), Scopes: strings.Join(g.Scopes, " "), First: when(g.First), Last: when(g.Last)})
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

func muted(s string) templ.Component {
	return nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(s))
}

func row(left, right templ.Component, testid string) templ.Component {
	return nest(box.Box(box.BoxProps{Class: "flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4", Attrs: af.A("data-testid", testid)}), many(
		nest(af.Stack("1", "start", "", "min-w-0", nil), left), right))
}

// PortalSSO renders Apps / Приложения: signed-in apps (revoke one) and sessions (end one, others, everywhere).
func PortalSSO(title, lead, csrf, info string, labels map[string]any, apps []SSOApp, sessions []SSOSession) templ.Component {
	appRows := make([]templ.Component, 0, len(apps))
	for _, a := range apps {
		appRows = append(appRows, row(many(
			nest(text.Text(text.TextProps{Class: "font-semibold"}), textNode(a.Name)),
			muted(labStr(labels, "scopes")+": "+a.Scopes),
			nest(text.Text(text.TextProps{Class: af.TextHint}), textNode(labStr(labels, "first")+" "+a.First+" · "+labStr(labels, "last")+" "+a.Last)),
		), nest(af.Form("/account/apps/client/revoke", "", nil), many(
			af.Hidden("csrf", csrf), af.Hidden("client", a.ClientID),
			outlineSubmit("revoke-"+a.ClientID, labStr(labels, "revoke")),
		)), "app-"+a.ClientID))
	}
	if len(apps) == 0 {
		appRows = append(appRows, muted(labStr(labels, "empty")))
	}
	sessRows := make([]templ.Component, 0, len(sessions))
	for _, ss := range sessions {
		head := ss.Device
		if ss.Current {
			head = labStr(labels, "current") + " · " + head
		}
		meta := labStr(labels, "ip") + " " + ss.IP + " · " + labStr(labels, "created") + " " + ss.Created + " · " + labStr(labels, "lastSeen") + " " + ss.LastSeen
		left := many(
			nest(text.Text(text.TextProps{Class: "font-semibold break-all"}), textNode(head)),
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
		sessRows = append(sessRows, muted(labStr(labels, "noSessions")))
	}
	return portalStack(
		sectionTitle("apps", title, lead),
		flash(info),
		nest(af.Stack("4", "start", "", "w-full", af.A("data-testid", "sso-apps")), many(
			af.Title(2, "apps-signed-in", "", labStr(labels, "appsTitle")),
			many(appRows...),
		)),
		nest(af.Stack("4", "start", "", "w-full", af.A("data-testid", "sso-sessions")), many(
			af.Title(2, "apps-sessions", "", labStr(labels, "sessionsTitle")),
			many(sessRows...),
			nest(box.Box(box.BoxProps{Class: "flex flex-wrap gap-4"}), many(
				nest(af.Form("/account/sessions/others", "", nil), many(af.Hidden("csrf", csrf), outlineSubmit("sign-out-others", labStr(labels, "others")))),
				nest(af.Form("/account/sessions/everywhere", "", nil), many(af.Hidden("csrf", csrf), submitBtn("sign-out-everywhere", labStr(labels, "everywhere")))),
			)),
		)),
	)
}

var _ = idp.PathLogin

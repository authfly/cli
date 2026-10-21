package main

// Logs, GDPR overview and guided scenarios.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authfly/authfly/server/core"
)

func auditTable(events []core.AuditEvent) *Table {
	t := &Table{Cols: []string{"Time (UTC)", "Action", "Outcome", "Actor", "Subject", "Detail"}, Empty: "No events."}
	for _, e := range events {
		var d []string
		for k, v := range e.Detail {
			d = append(d, k+"="+v)
		}
		t.Rows = append(t.Rows, Row{Cells: []string{strings.Replace(e.Time[:min(19, len(e.Time))], "T", " ", 1), e.Action, e.Outcome, e.Actor, e.Subject, strings.Join(d, " ")}})
	}
	return t
}

func (c *Console) logsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subject := r.URL.Query().Get("subject")
	n, broken := c.Audit.Verify()
	chain := fmt.Sprintf("%d entries, hash chain intact", n)
	if broken >= 0 {
		chain = fmt.Sprintf("%d entries, chain BROKEN at entry %d", n, broken)
	}
	bl := []Block{{Kind: "form", Title: "Filter", Icon: "filter", Form: &FormVM{ID: "filter", Action: "/logs", Submit: "Filter", Variant: "outline", Inline: true,
		Fields: []Field{{Name: "subject", Label: "Subject (address or pseudonym)", Kind: "text", Value: subject}}}}}
	_ = bl
	bl = []Block{{Kind: "table", Title: "Console actions", Icon: "terminal", Badge: chain, Text: "Every sign-in, change, request and GDPR action taken in this console (CONSOLE_DATA/console-audit.jsonl).", Table: auditTable(c.Audit.Query(subject, 200))}}
	var ak struct {
		Events      []core.AuditEvent `json:"events"`
		Total       int               `json:"total"`
		ChainIntact bool              `json:"chainIntact"`
	}
	path := "/admin/v1/audit?limit=200"
	if subject != "" {
		path += "&subject=" + q(subject)
	}
	if _, _, err := c.authfly(ctx, "", "GET", path, &ak); err == nil {
		badge := fmt.Sprintf("%d entries, hash chain intact", ak.Total)
		if !ak.ChainIntact {
			badge = fmt.Sprintf("%d entries, chain BROKEN", ak.Total)
		}
		bl = append(bl, Block{Kind: "table", Title: "Authfly audit log", Icon: "scroll-text", Badge: badge, Text: "Sign-ups, sign-ins, verifications, resets, consents, exports and erasures. No IP addresses are stored.", Table: auditTable(ak.Events)})
	} else {
		bl = append(bl, errBlock("Authfly audit log unavailable", err))
	}
	if _, err := c.call(ctx, "x:Log/query", map[string]any{"limit": 1}); err != nil {
		bl = append(bl, Block{Kind: "alert", Icon: "info", Title: "Stalwart server log", Text: "x:Log is unavailable (" + err.Error() + "): no log store is configured in this deployment. Use `docker compose logs stalwart`."})
	} else {
		bl = append(bl, Block{Kind: "links", Title: "Stalwart server log", Icon: "file-text", Links: []Link{{Label: "Open x:Log", Href: "/object?v=x:Log", Icon: "file-text"}}})
	}
	c.show(w, r, 200, c.page(r, "Logs and audit", "Tamper-evident logs of the console and of Authfly.", "/logs", bl...))
}

func (c *Console) gdprPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var bl []Block
	if d, err := c.getOne(ctx, "x:DataRetention", "singleton"); err == nil {
		kv := [][2]string{}
		for _, k := range []string{"archiveDeletedAccountsFor", "archiveDeletedItemsFor", "expungeTrashAfter", "expungeSubmissionsAfter", "holdTracesFor", "holdMetricsFor"} {
			if v, ok := d[k]; ok {
				kv = append(kv, [2]string{k, nonEmpty(cell(v), "null (off)")})
			}
		}
		bl = append(bl, Block{Kind: "card", Title: "Stalwart retention", Icon: "timer", Text: "x:DataRetention. archiveDeletedAccountsFor must stay null for erasure to be immediate.", KV: kv,
			Links: []Link{{Label: "Edit retention settings", Href: "/object?v=x:DataRetention", Icon: "pencil"}}})
	} else {
		bl = append(bl, errBlock("x:DataRetention", err))
	}
	var ret struct {
		AuditRetention string `json:"auditRetention"`
	}
	_, _, aerr := c.authfly(ctx, "", "GET", "/admin/v1/retention", &ret)
	rk := [][2]string{{"Audit log retention", nonEmpty(ret.AuditRetention, "unknown")}, {"Pruning", "daily, and on demand below"}, {"Session revocation", "per address, on erasure, password reset, sign out everywhere"}}
	if aerr != nil {
		rk = append(rk, [2]string{"Admin API", aerr.Error()})
	}
	bl = append(bl, Block{Kind: "form", Title: "Authfly retention", Icon: "history", Text: "AUTHFLY_AUDIT_RETENTION. Entries older than this are removed from the audit log.", KV: rk,
		Form: &FormVM{ID: "retention", Action: "/gdpr/retention", Submit: "Run retention now", Variant: "outline"}})
	if e, err := c.getOne(ctx, "x:Email", "singleton"); err == nil {
		bl = append(bl, Block{Kind: "card", Title: "Encryption at rest", Icon: "lock", Text: "Users can encrypt stored mail with their own OpenPGP or S/MIME key (x:Account.encryptionAtRest).",
			KV: [][2]string{{"x:Email.encryptAtRest (allowed)", cell(e["encryptAtRest"])}, {"Volumes", "Encrypt the stalwart-data and authfly-data volumes at the disk level (LUKS or the cloud provider's disk encryption); see docs/gdpr.md."}}})
	}
	users := c.options(ctx, "x:Account/User")
	bl = append(bl, Block{Kind: "card", Title: "Requests by person", Icon: "user-search", Text: "Open a user to export (access, portability) or erase (right to be forgotten). Both are logged.",
		Links: func() []Link {
			var l []Link
			for _, u := range users {
				l = append(l, Link{Label: u.Label, Href: "/users/view?id=" + q(u.Name), Icon: "user"})
			}
			return l
		}()},
		Block{Kind: "card", Title: "What the GDPR features cover", Icon: "book-open", Items: []string{
			"Export (Art. 15, 20): account record without credentials, Authfly records, consents, audit trail, mailboxes, identities and messages with text bodies.",
			"Erasure (Art. 17): Stalwart account and mailbox destroyed, Authfly sessions revoked, records deleted, audit pseudonymised; verified live.",
			"Consent (Art. 7): terms acceptance at sign-up and every OIDC consent decision, with time, client and scopes.",
			"Accountability (Art. 5(2)): hash-chained audit logs for Authfly and for this console, without IP addresses.",
			"Self-service API: GET /api/v1/me/export, GET /api/v1/me/consents, DELETE /api/v1/me (password required).",
		}})
	c.show(w, r, 200, c.page(r, "GDPR", "Data subject requests, retention and encryption.", "/gdpr", bl...))
}

func (c *Console) gdprRetention(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Pruned int `json:"pruned"`
	}
	_, _, err := c.authfly(r.Context(), session(r).User, "POST", "/admin/v1/retention/run", &out)
	c.log(r, "gdpr.retention", "", map[bool]string{true: "ok", false: "error"}[err == nil], map[string]string{"pruned": fmt.Sprint(out.Pruned)})
	if err != nil {
		c.show(w, r, 502, c.page(r, "GDPR", "", "/gdpr", errBlock("Retention failed", err)))
		return
	}
	c.show(w, r, 200, c.page(r, "GDPR", "", "/gdpr", Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Retention ran", Text: fmt.Sprintf("%d audit entries pruned.", out.Pruned)},
		Block{Kind: "links", Links: []Link{{Label: "Back to GDPR", Href: "/gdpr", Icon: "arrow-left"}}}))
}

// ---- scenarios

func (c *Console) scenariosPage(w http.ResponseWriter, r *http.Request) {
	c.show(w, r, 200, c.page(r, "Scenarios", "Guided flows that chain several API calls with checks.", "/scenarios", Block{Kind: "card", Title: "Available", Icon: "wand-sparkles", Links: scenarioLinks()}))
}

func (c *Console) onboardFields(r *http.Request, vals map[string]string) []Field {
	domains := c.options(r.Context(), "x:Domain")
	def := vals["domainId"]
	for _, d := range domains {
		if def == "" && strings.HasPrefix(d.Label, c.Domain) {
			def = d.Name
		}
	}
	return []Field{
		{Name: "name", Label: "Username", Kind: "text", Required: true, Value: vals["name"], Desc: "The test user to create."},
		{Name: "domainId", Label: "Domain", Kind: "ref", Ref: "x:Domain", Required: true, Value: def, Options: domains, Desc: "Prefilled from the live domains."},
		{Name: "password", Label: "Password", Kind: "password", Required: true, Desc: "At least 10 characters."},
		{Name: "clientId", Label: "OIDC client id", Kind: "text", Required: true, Value: vals["clientId"], Desc: "Registered as x:OAuthClient; required because requireClientRegistration is on."},
		{Name: "redirect", Label: "Redirect URI", Kind: "text", Format: "uri", Required: true, Value: nonEmpty(vals["redirect"], "http://localhost:3000/callback"), Desc: "Where the application receives the code."},
	}
}

func (c *Console) onboardPage(w http.ResponseWriter, r *http.Request) {
	c.onboardView(w, r, 200, c.onboardFields(r, map[string]string{}), nil)
}

func (c *Console) onboardView(w http.ResponseWriter, r *http.Request, status int, fields []Field, top []Block) {
	bl := append(top,
		Block{Kind: "card", Title: "What happens", Icon: "list-ordered", Steps: []Step{
			{"1. Create the user", "skip", "x:Account/set create (mailbox created at once)"},
			{"2. Register the OIDC client", "skip", "x:OAuthClient/set create with the redirect URI"},
			{"3. Test sign-in", "skip", "POST /api/auth (authorization code, PKCE) → POST /auth/token → GET /auth/userinfo, as a real relying party would"},
			{"4. Verify the ID token", "skip", "signature against the JWKS, audience = client id"},
		}},
		Block{Kind: "form", Title: "Onboard an application", Icon: "rocket", Text: "Stops at the first failing step and tells you what to fix.", Form: &FormVM{ID: "onboard", Action: "/scenarios/onboard", Submit: "Run scenario", Fields: fields}})
	p := c.page(r, "Onboard an application", "User + OIDC client + test sign-in, as one guided flow.", "/scenarios", bl...)
	p.Crumbs = []Link{{Label: "Scenarios", Href: "/scenarios"}}
	c.show(w, r, status, p)
}

func (c *Console) onboardRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vals := map[string]string{}
	for _, k := range []string{"name", "domainId", "clientId", "redirect"} {
		vals[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	pw := r.PostFormValue("password")
	fields := c.onboardFields(r, vals)
	bad := 0
	for i := range fields {
		f := &fields[i]
		switch f.Name {
		case "name":
			if !reUser(vals["name"]) {
				f.Err = "1–64 characters: letters, digits, dot, dash, underscore"
			}
		case "domainId":
			if _, _, err := f.Parse(vals["domainId"], true); err != nil {
				f.Err = err.Error()
			}
		case "password":
			if len(pw) < 10 {
				f.Err = "at least 10 characters"
			}
		case "clientId":
			if !reUser(vals["clientId"]) {
				f.Err = "letters, digits, dot, dash, underscore"
			}
		case "redirect":
			if _, _, err := f.Parse(vals["redirect"], true); err != nil {
				f.Err = err.Error()
			}
		}
		if f.Err != "" {
			bad++
		}
	}
	if bad > 0 {
		c.onboardView(w, r, 422, fields, []Block{{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: fmt.Sprintf("%d field(s) need attention", bad), Text: "Nothing was created."}})
		return
	}
	var steps []Step
	fail := func(t string, err error, fix string) {
		steps = append(steps, Step{t, "fail", err.Error() + ". " + fix})
	}
	ok := func(t, d string) { steps = append(steps, Step{t, "ok", d}) }
	run := func() {
		acc := map[string]any{"@type": "User", "name": vals["name"], "domainId": vals["domainId"], "description": "Onboarding test user",
			"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": pw}}, "roles": map[string]any{"@type": "User"},
			"permissions": map[string]any{"@type": "Inherit"}, "encryptionAtRest": map[string]any{"@type": "Disabled"}}
		out, err := c.call(ctx, "x:Account/set", map[string]any{"create": map[string]any{"u": acc}})
		var uid string
		if err == nil {
			uid, err = setResult(out)
		}
		if err != nil {
			fail("Create the user", err, "If the name is taken, pick another one or delete the old user.")
			return
		}
		u, _ := c.getOne(ctx, "x:Account", uid)
		addr := cell(u["emailAddress"])
		ok("Create the user", fmt.Sprintf("%s (id %s)", addr, uid))
		out, err = c.call(ctx, "x:OAuthClient/set", map[string]any{"create": map[string]any{"c": map[string]any{"clientId": vals["clientId"], "description": "Onboarded with the Authfly Console", "redirectUris": map[string]bool{vals["redirect"]: true}}}})
		var cid string
		if err == nil {
			cid, err = setResult(out)
		}
		if err != nil {
			fail("Register the OIDC client", err, "A client with this id may exist already: open OIDC clients.")
			return
		}
		ok("Register the OIDC client", fmt.Sprintf("%s (id %s), redirect %s", vals["clientId"], cid, vals["redirect"]))
		verifier, challenge := core.PKCE()
		nonce := core.RandomString(12)
		code, err := c.SW.Authorize(ctx, core.AuthCodeRequest{AccountName: addr, AccountSecret: pw, ClientID: vals["clientId"], RedirectURI: vals["redirect"], Scope: "openid email profile", Nonce: nonce, CodeChallenge: challenge})
		if err != nil {
			fail("Test sign-in: authorization code", err, "Check that the client is registered and the password is right.")
			return
		}
		ok("Test sign-in: authorization code", "code issued for "+vals["redirect"])
		tok, err := c.SW.Exchange(ctx, vals["clientId"], "", code, vals["redirect"], verifier)
		if err != nil {
			fail("Test sign-in: token exchange", err, "The redirect URI must match exactly.")
			return
		}
		ok("Test sign-in: token exchange", "access token and ID token received")
		info, err := c.SW.UserInfo(ctx, tok.AccessToken)
		if err != nil {
			fail("Test sign-in: userinfo", err, "")
			return
		}
		ok("Test sign-in: userinfo", fmt.Sprintf("sub=%v email=%v", info["sub"], info["email"]))
		if claims, err := c.SW.VerifyIDToken(ctx, tok.IDToken, vals["clientId"], nonce); err != nil {
			fail("Verify the ID token", err, "")
		} else {
			ok("Verify the ID token", fmt.Sprintf("signature valid, aud=%v, iss=%v", claims["aud"], claims["iss"]))
		}
	}
	run()
	outcome := "ok"
	for _, s := range steps {
		if s.Status == "fail" {
			outcome = "error"
		}
	}
	c.invalidate()
	c.log(r, "scenario.onboard", vals["name"], outcome, map[string]string{"client": vals["clientId"]})
	tone, title := "success", "Scenario passed"
	if outcome != "ok" {
		tone, title = "destructive", "Scenario stopped"
	}
	next := []Link{{Label: "Open users", Href: "/users", Icon: "users"}, {Label: "Open OIDC clients", Href: "/object?v=x:OAuthClient", Icon: "key-round"}, {Label: "Run again", Href: "/scenarios/onboard", Icon: "rotate-ccw"}}
	p := c.page(r, "Onboard an application", "", "/scenarios",
		Block{Kind: "alert", Tone: tone, Icon: map[bool]string{true: "circle-check", false: "circle-x"}[outcome == "ok"], Title: title},
		Block{Kind: "card", Title: "Steps", Icon: "list-checks", Steps: steps},
		Block{Kind: "card", Title: "Next", Icon: "arrow-right", Text: "Configure your application with these values: issuer " + c.PublicURL + ", client id " + vals["clientId"] + ", redirect " + vals["redirect"] + ", PKCE S256, no client secret.", Links: next})
	p.Crumbs = []Link{{Label: "Scenarios", Href: "/scenarios"}}
	c.show(w, r, map[bool]int{true: 200, false: 400}[outcome == "ok"], p)
}

func (c *Console) lockdownRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var steps []Step
	do := func(t string, f func(context.Context) error) {
		if err := f(ctx); err != nil {
			steps = append(steps, Step{t, "fail", err.Error()})
		} else {
			steps = append(steps, Step{t, "ok", ""})
		}
	}
	do("OIDC: anonymous registration off, registered clients only", func(ctx context.Context) error {
		out, err := c.call(ctx, "x:OidcProvider/set", map[string]any{"update": map[string]any{"singleton": map[string]any{"anonymousClientRegistration": false, "requireClientRegistration": true}}})
		if err == nil {
			_, err = setResult(out)
		}
		return err
	})
	do("Web admin and account apps disabled", func(ctx context.Context) error {
		apps, _, err := c.list(ctx, c.Schema.Views["x:Application"], 20, []string{"id"})
		if err != nil {
			return err
		}
		upd := map[string]any{}
		for _, a := range apps {
			upd[fmt.Sprint(a["id"])] = map[string]any{"enabled": false}
		}
		if len(upd) == 0 {
			return nil
		}
		out, err := c.call(ctx, "x:Application/set", map[string]any{"update": upd})
		if err == nil {
			_, err = setResult(out)
		}
		return err
	})
	do("Apply: UpdateApps and ReloadSettings", func(ctx context.Context) error {
		for _, a := range []string{"UpdateApps", "ReloadSettings"} {
			out, err := c.call(ctx, "x:Action/set", map[string]any{"create": map[string]any{"a": map[string]any{"@type": a}}})
			if err == nil {
				_, err = setResult(out)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	c.log(r, "scenario.lockdown", "", "ok", nil)
	time.Sleep(300 * time.Millisecond)
	c.show(w, r, 200, c.page(r, "Lock-down", "", "/",
		Block{Kind: "card", Title: "Applied", Icon: "shield-check", Steps: steps},
		Block{Kind: "card", Title: "Live checks", Icon: "list-checks", Steps: c.lockdownChecks(ctx)}))
}

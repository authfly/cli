package main

// Users: the higher-level view over x:Account/User with Authkit's state (verification, consents, audit) next to it,
// and the GDPR actions.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ui8kit/authkit/server/core"
)

func (c *Console) userFields(r *http.Request, vals map[string]string) []Field {
	ctx := r.Context()
	domains := c.options(ctx, "x:Domain")
	defDomain := vals["domainId"]
	for _, d := range domains {
		if defDomain == "" && strings.HasPrefix(d.Label, c.Domain) {
			defDomain = d.Name
		}
	}
	roles := []EnumItem{{"User", "User (built-in)"}, {"Admin", "Admin (built-in, full access)"}}
	for _, ro := range c.options(ctx, "x:Role") {
		roles = append(roles, EnumItem{"custom:" + ro.Name, "Custom role: " + ro.Label})
	}
	return []Field{
		{Name: "name", Label: "Username", Kind: "text", Required: true, Value: vals["name"], Desc: "Local part of the address: letters, digits, dot, dash, underscore.", Type: TypeDef{MaxLength: 64}},
		{Name: "domainId", Label: "Domain", Kind: "ref", Ref: "x:Domain", Required: true, Value: defDomain, Options: domains, Desc: "Prefilled from the live domains; the address is username@domain."},
		{Name: "description", Label: "Full name", Kind: "text", Value: vals["description"]},
		{Name: "password", Label: "Password", Kind: "password", Required: true, Desc: "At least 10 characters. The user can change it with Authkit's reset flow.", Type: TypeDef{MinLength: 10}},
		{Name: "role", Label: "Role", Kind: "select", Required: true, Value: nonEmpty(vals["role"], "User"), Options: roles, Desc: "Prefilled from the live roles. Admin grants full management access: avoid it for end users."},
	}
}

var reUser = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (c *Console) usersPage(w http.ResponseWriter, r *http.Request) {
	c.usersView(w, r, 200, nil, nil)
}

func (c *Console) usersView(w http.ResponseWriter, r *http.Request, status int, fields []Field, top []Block) {
	ctx := r.Context()
	v := c.Schema.Views["x:Account/User"]
	bl := append([]Block{}, top...)
	items, total, err := c.list(ctx, v, 200, []string{"id", "name", "emailAddress", "description", "createdAt", "roles"})
	if err != nil {
		bl = append(bl, errBlock("Could not list users", err))
	} else {
		t := &Table{Cols: []string{"Address", "Name", "Role", "Created"}, Empty: "No users yet."}
		for _, o := range items {
			t.Rows = append(t.Rows, Row{Cells: []string{cell(o["emailAddress"]), cell(o["description"]), cell(o["roles"]), cell(o["createdAt"])}, Href: "/users/view?id=" + q(fmt.Sprint(o["id"]))})
		}
		bl = append(bl, Block{Kind: "table", Title: "Users", Badge: fmt.Sprint(total), Icon: "users", Table: t})
	}
	if fields == nil {
		fields = c.userFields(r, map[string]string{})
	}
	bl = append(bl, Block{Kind: "form", Title: "New user", Icon: "user-plus", Text: "Creates the Stalwart account and its mailbox (x:Account/set create).", Form: &FormVM{ID: "user-create", Action: "/users/create", Submit: "Create user", Fields: fields}})
	bl = append(bl, c.objectIntro(v)[1:]...)
	c.show(w, r, status, c.page(r, "Users", "Mail accounts that sign in with Authkit.", "/users", bl...))
}

func (c *Console) usersCreate(w http.ResponseWriter, r *http.Request) {
	vals := map[string]string{}
	for _, k := range []string{"name", "domainId", "description", "role"} {
		vals[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	fields := c.userFields(r, vals)
	bad := 0
	set := func(name, msg string) {
		for i := range fields {
			if fields[i].Name == name {
				fields[i].Err = msg
			}
		}
		bad++
	}
	if !reUser(vals["name"]) {
		set("name", "1–64 characters: letters, digits, dot, dash, underscore")
	}
	okDomain := false
	for _, d := range fields[1].Options {
		okDomain = okDomain || d.Name == vals["domainId"]
	}
	if !okDomain {
		set("domainId", "pick an existing domain")
	}
	pw := r.PostFormValue("password")
	if len(pw) < 10 {
		set("password", "at least 10 characters")
	}
	roles := map[string]any{"@type": "User"}
	switch {
	case vals["role"] == "Admin":
		roles = map[string]any{"@type": "Admin"}
	case strings.HasPrefix(vals["role"], "custom:"):
		roles = map[string]any{"@type": "Custom", "roleIds": map[string]bool{strings.TrimPrefix(vals["role"], "custom:"): true}}
	case vals["role"] != "User":
		set("role", "pick a role")
	}
	if bad > 0 {
		c.usersView(w, r, 422, fields, []Block{{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: fmt.Sprintf("%d field(s) need attention", bad), Text: "Nothing was sent to Stalwart."}})
		return
	}
	acc := map[string]any{"@type": "User", "name": vals["name"], "domainId": vals["domainId"], "description": vals["description"],
		"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": pw}}, "roles": roles,
		"permissions": map[string]any{"@type": "Inherit"}, "encryptionAtRest": map[string]any{"@type": "Disabled"}}
	out, err := c.call(r.Context(), "x:Account/set", map[string]any{"create": map[string]any{"u": acc}})
	var id string
	if err == nil {
		id, err = setResult(out)
	}
	c.invalidate()
	if err != nil {
		c.log(r, "user.create", vals["name"], "error", map[string]string{"error": err.Error()})
		c.usersView(w, r, 400, fields, []Block{errBlock("Stalwart refused the account", err)})
		return
	}
	c.log(r, "user.create", vals["name"], "ok", map[string]string{"id": id, "role": vals["role"]})
	http.Redirect(w, r, "/users/view?id="+q(id)+"&created=1", http.StatusSeeOther)
}

func (c *Console) userPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var top []Block
	if r.URL.Query().Get("created") != "" {
		top = append(top, Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "User created", Text: "The mailbox exists now. The user verifies the address through Authkit."})
	}
	if r.URL.Query().Get("saved") != "" {
		top = append(top, Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Saved"})
	}
	c.userView(w, r, 200, id, top, nil)
}

func (c *Console) userView(w http.ResponseWriter, r *http.Request, status int, id string, top []Block, edit []Field) {
	ctx := r.Context()
	acc, err := c.getOne(ctx, "x:Account", id)
	if err != nil {
		c.show(w, r, 404, c.page(r, "User", "", "/users", errBlock("Not found", err)))
		return
	}
	addr := cell(acc["emailAddress"])
	bl := append([]Block{}, top...)
	bl = append(bl, Block{Kind: "card", Title: "Account", Icon: "user", KV: [][2]string{
		{"Address", addr}, {"Id", id}, {"Full name", cell(acc["description"])}, {"Role", cell(acc["roles"])},
		{"Created", cell(acc["createdAt"])}, {"Disk used", cell(acc["usedDiskQuota"]) + " bytes"}, {"Encryption at rest", cell(acc["encryptionAtRest"])},
	}})
	var ak struct {
		Authkit map[string]any   `json:"authkit"`
		Audit   []map[string]any `json:"audit"`
	}
	if _, _, err := c.authkit(ctx, "", "GET", "/admin/v1/users/"+pathAddr(addr), &ak); err == nil {
		kv := [][2]string{{"Email verified", nonEmpty(cell(ak.Authkit["email_verified_at"]), "not yet")}, {"Sessions revoked at", nonEmpty(cell(ak.Authkit["sessions_revoked_at"]), "never")}}
		if cs, ok := ak.Authkit["consents"].([]any); ok {
			for _, x := range cs {
				m, _ := x.(map[string]any)
				kv = append(kv, [2]string{"Consent " + cell(m["kind"]) + " " + cell(m["client"]), fmt.Sprintf("%v at %v %v", map[bool]string{true: "granted", false: "denied"}[m["granted"] == true], m["time"], cell(m["scopes"]))})
			}
		}
		bl = append(bl, Block{Kind: "card", Title: "Authkit", Icon: "shield-check", Text: "What Authkit holds about this person (store and consent records).", KV: kv})
		t := &Table{Cols: []string{"Time", "Action", "Outcome", "Actor"}, Empty: "No audit events."}
		for _, e := range ak.Audit {
			t.Rows = append(t.Rows, Row{Cells: []string{cell(e["time"]), cell(e["action"]), cell(e["outcome"]), cell(e["actor"])}})
		}
		bl = append(bl, Block{Kind: "table", Title: "Audit trail", Icon: "scroll-text", Table: t})
	} else {
		bl = append(bl, Block{Kind: "alert", Tone: "warning", Icon: "triangle-alert", Title: "Authkit admin API unreachable", Text: err.Error()})
	}
	if edit == nil {
		edit = []Field{
			{Name: "description", Label: "Full name", Kind: "text", Value: cell(acc["description"])},
			{Name: "password", Label: "New password", Kind: "password", Desc: "Leave empty to keep the current password. Setting one also signs the user out of Authkit everywhere.", Type: TypeDef{MinLength: 10}},
		}
	}
	bl = append(bl,
		Block{Kind: "form", Title: "Edit", Icon: "pencil", Form: &FormVM{ID: "user-edit", Action: "/users/update", Submit: "Save", Hidden: [][2]string{{"id", id}}, Fields: edit}},
		Block{Kind: "form", Title: "Sessions", Icon: "log-out", Text: "Revoke every Authkit session of this user (sign out everywhere).", Form: &FormVM{ID: "user-revoke", Action: "/users/revoke", Submit: "Sign out everywhere", Variant: "outline", Hidden: [][2]string{{"id", id}}}},
		Block{Kind: "links", Title: "GDPR: right of access (Art. 15, 20)", Icon: "file-down", Text: "A JSON file with the account, Authkit's records, the audit trail and the mailbox. The download is logged.", Links: []Link{{Label: "Download export", Href: "/users/export?id=" + q(id), Icon: "download", Text: addr + ".json"}}},
		Block{Kind: "form", Title: "GDPR: right to erasure (Art. 17)", Icon: "user-x", Tone: "destructive", Text: "Removes the account and mailbox in Stalwart, Authkit's sessions and records, and pseudonymises the audit log. Asks for confirmation.",
			Form: &FormVM{ID: "user-erase", Action: "/users/erase", Submit: "Erase…", Variant: "destructive", Hidden: [][2]string{{"id", id}}}},
		Block{Kind: "form", Title: "Delete account only", Icon: "trash-2", Text: "Deletes the Stalwart account without the GDPR steps (Authkit keeps its records). Prefer erasure for people.",
			Form: &FormVM{ID: "user-delete", Action: "/users/delete", Submit: "Delete…", Variant: "outline", Hidden: [][2]string{{"id", id}}}},
	)
	p := c.page(r, addr, "User account", "/users", bl...)
	p.Crumbs = []Link{{Label: "Users", Href: "/users"}}
	c.show(w, r, status, p)
}

func (c *Console) userUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	ctx := r.Context()
	acc, err := c.getOne(ctx, "x:Account", id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	patch := map[string]any{}
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if desc != cell(acc["description"]) {
		patch["description"] = desc
	}
	pw := r.PostFormValue("password")
	if pw != "" {
		if len(pw) < 10 {
			c.userView(w, r, 422, id, []Block{{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: "Not saved", Text: "Nothing was sent to Stalwart."}},
				[]Field{{Name: "description", Label: "Full name", Kind: "text", Value: desc}, {Name: "password", Label: "New password", Kind: "password", Err: "at least 10 characters"}})
			return
		}
		patch["credentials"] = map[string]any{"0": map[string]any{"@type": "Password", "secret": pw}}
	}
	if len(patch) == 0 {
		http.Redirect(w, r, "/users/view?id="+q(id), http.StatusSeeOther)
		return
	}
	out, err := c.call(ctx, "x:Account/set", map[string]any{"update": map[string]any{id: patch}})
	if err == nil {
		_, err = setResult(out)
	}
	if err != nil {
		c.log(r, "user.update", cell(acc["emailAddress"]), "error", map[string]string{"error": err.Error()})
		c.userView(w, r, 400, id, []Block{errBlock("Stalwart refused the change", err)}, nil)
		return
	}
	if pw != "" {
		_, _, _ = c.authkit(ctx, session(r).User, "POST", "/admin/v1/users/"+pathAddr(cell(acc["emailAddress"]))+"/revoke", nil)
	}
	c.log(r, "user.update", cell(acc["emailAddress"]), "ok", map[string]string{"fields": strings.Join(keys(patch), ",")})
	http.Redirect(w, r, "/users/view?id="+q(id)+"&saved=1", http.StatusSeeOther)
}

func (c *Console) userRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	acc, err := c.getOne(r.Context(), "x:Account", id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := cell(acc["emailAddress"])
	_, _, err = c.authkit(r.Context(), session(r).User, "POST", "/admin/v1/users/"+pathAddr(addr)+"/revoke", nil)
	top := []Block{{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Signed out everywhere", Text: "Every Authkit session issued before now is invalid."}}
	if err != nil {
		top = []Block{errBlock("Could not revoke", err)}
	}
	c.log(r, "user.revoke", addr, map[bool]string{true: "ok", false: "error"}[err == nil], nil)
	c.userView(w, r, 200, id, top, nil)
}

func (c *Console) userDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	ctx := r.Context()
	acc, err := c.getOne(ctx, "x:Account", id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := cell(acc["emailAddress"])
	if r.PostFormValue("confirm") != addr {
		c.confirm(w, r, "Delete "+addr, append(c.dangerItems(c.Schema.Views["x:Account/User"], acc), "Authkit keeps its records (consents, audit). Use erasure to remove those too."),
			"/users/delete", [][2]string{{"id", id}}, addr, r.PostFormValue("confirm") != "")
		return
	}
	out, err := c.call(ctx, "x:Account/set", map[string]any{"destroy": []string{id}})
	if err == nil {
		_, err = setResult(out)
	}
	c.invalidate()
	if err != nil {
		c.log(r, "user.delete", addr, "error", map[string]string{"error": err.Error()})
		c.usersView(w, r, 400, nil, []Block{errBlock("Stalwart refused the deletion", err)})
		return
	}
	c.log(r, "user.delete", addr, "ok", map[string]string{"id": id})
	c.usersView(w, r, 200, nil, []Block{{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Deleted", Text: addr + " was deleted."}})
}

func (c *Console) userExport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	acc, err := c.getOne(r.Context(), "x:Account", id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := cell(acc["emailAddress"])
	_, b, err := c.authkit(r.Context(), session(r).User, "GET", "/admin/v1/users/"+pathAddr(addr)+"/export", nil)
	if err != nil {
		c.log(r, "gdpr.export", addr, "error", map[string]string{"error": err.Error()})
		c.userView(w, r, 502, id, []Block{errBlock("Export failed", err)}, nil)
		return
	}
	c.log(r, "gdpr.export", addr, "ok", map[string]string{"bytes": fmt.Sprint(len(b))})
	var pretty any
	_ = json.Unmarshal(b, &pretty)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="authkit-export-%s.json"`, strings.ReplaceAll(addr, "@", "_at_")))
	_, _ = w.Write([]byte(jsonPretty(pretty)))
}

func (c *Console) userErase(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	ctx := r.Context()
	acc, err := c.getOne(ctx, "x:Account", id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := cell(acc["emailAddress"])
	if r.PostFormValue("confirm") != addr {
		items := []string{"The Stalwart account " + addr + " and its whole mailbox are destroyed.", "Every Authkit session is revoked; verification and consent records are deleted.",
			"The audit log keeps the events under a pseudonym (accountability, Art. 5(2)).", "Consider downloading the export first: after erasure nothing can be recovered."}
		if d, err := c.getOne(ctx, "x:DataRetention", "singleton"); err == nil && d["archiveDeletedAccountsFor"] != nil {
			items = append(items, fmt.Sprintf("WARNING: x:DataRetention.archiveDeletedAccountsFor is %v, so Stalwart Enterprise keeps an archive.", d["archiveDeletedAccountsFor"]))
		}
		c.confirm(w, r, "Erase "+addr, items, "/users/erase", [][2]string{{"id", id}}, addr, r.PostFormValue("confirm") != "")
		return
	}
	var rep struct {
		Pseudonym          string   `json:"pseudonym"`
		MessagesBefore     int      `json:"messagesBefore"`
		AuditPseudonymised int      `json:"auditPseudonymised"`
		Steps              []string `json:"steps"`
	}
	_, _, err = c.authkit(ctx, session(r).User, "POST", "/admin/v1/users/"+pathAddr(addr)+"/erase", &rep)
	c.invalidate()
	if err != nil {
		c.log(r, "gdpr.erase", addr, "error", map[string]string{"error": err.Error()})
		c.userView(w, r, 502, id, []Block{errBlock("Erasure failed", err)}, nil)
		return
	}
	// verify in Stalwart that the account is gone
	_, gone := c.getOne(ctx, "x:Account", id)
	steps := []Step{}
	for _, s := range rep.Steps {
		steps = append(steps, Step{s, "ok", ""})
	}
	steps = append(steps, boolStep("Verified: x:Account/get "+id+" returns nothing", gone != nil, "checked live after erasure"))
	c.log(r, "gdpr.erase", core.Pseudonym(addr), "ok", map[string]string{"messages": fmt.Sprint(rep.MessagesBefore)})
	c.Audit.Pseudonymise(addr)
	c.show(w, r, 200, c.page(r, "Erased", "", "/users",
		Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Erasure complete", Text: fmt.Sprintf("%d messages removed; the person is now %s in the audit logs.", rep.MessagesBefore, rep.Pseudonym)},
		Block{Kind: "card", Title: "What was done", Icon: "list-checks", Steps: steps},
		Block{Kind: "links", Links: []Link{{Label: "Back to users", Href: "/users", Icon: "arrow-left"}}}))
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

var consoleNav = NavGroup{Title: "Console", Icon: "terminal", Items: []NavItem{
	{"Dashboard", "/"}, {"Users", "/users"}, {"Domains", "/object?v=x:Domain"}, {"Groups", "/object?v=x:Account/Group"},
	{"OIDC clients", "/object?v=x:OAuthClient"}, {"Roles", "/object?v=x:Role"}, {"Mail queue", "/object?v=x:QueuedMessage"},
	{"Logs and audit", "/logs"}, {"GDPR", "/gdpr"}, {"Scenarios", "/scenarios"}, {"Request builder", "/explorer"},
}}

func (c *Console) page(r *http.Request, title, sub, current string, bl ...Block) PageVM {
	s := session(r)
	nav := []NavGroup{consoleNav}
	for _, g := range c.Schema.Nav {
		ng := NavGroup{Title: g.Title, Icon: g.Icon}
		for _, it := range g.Items {
			ng.Items = append(ng.Items, NavItem{it.Label, "/object?v=" + it.View})
		}
		nav = append(nav, ng)
	}
	return PageVM{Title: title, Subtitle: sub, Current: current, User: s.User, Csrf: c.csrfFor(s), Nav: nav, Blocks: bl}
}

func (c *Console) show(w http.ResponseWriter, r *http.Request, status int, p PageVM) {
	render(w, r, status, layout(p))
}

func errBlock(title string, err error) Block {
	return Block{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: title, Text: err.Error()}
}

// ---- dashboard

func (c *Console) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	count := func(view string) string {
		v := c.Schema.Views[view]
		if v == nil {
			return "-"
		}
		_, total, err := c.list(ctx, v, 1, []string{"id"})
		if err != nil {
			return "n/a"
		}
		return fmt.Sprint(total)
	}
	stats := Block{Kind: "grid", Children: []Block{
		{Kind: "stat", Title: "Users", Badge: count("x:Account/User"), Icon: "users", Code: "/users"},
		{Kind: "stat", Title: "Domains", Badge: count("x:Domain"), Icon: "globe", Code: "/object?v=x:Domain"},
		{Kind: "stat", Title: "OIDC clients", Badge: count("x:OAuthClient"), Icon: "key-round", Code: "/object?v=x:OAuthClient"},
		{Kind: "stat", Title: "Groups", Badge: count("x:Account/Group"), Icon: "users-round", Code: "/object?v=x:Account/Group"},
		{Kind: "stat", Title: "Queued messages", Badge: count("x:QueuedMessage"), Icon: "send", Code: "/object?v=x:QueuedMessage"},
		{Kind: "stat", Title: "Roles", Badge: count("x:Role"), Icon: "shield", Code: "/object?v=x:Role"},
	}}
	checks := c.lockdownChecks(ctx)
	bad := 0
	for _, s := range checks {
		if s.Status == "fail" {
			bad++
		}
	}
	lock := Block{Kind: "card", Title: "Lock-down status", Icon: "shield-check", Text: "Live checks of the hardening init-stalwart applies (docs/security.md).", Steps: checks,
		Form: &FormVM{ID: "lockdown", Action: "/scenarios/lockdown", Submit: "Re-apply hardening", Variant: "outline", Note: "Runs the same idempotent steps as `authfly init-stalwart` for the parts the console owns (web UI off, OIDC registration locked)."}}
	var bl []Block
	if bad > 0 {
		bl = append(bl, Block{Kind: "alert", Tone: "destructive", Icon: "shield-alert", Title: fmt.Sprintf("%d lock-down check(s) failing", bad), Text: "Re-apply the hardening below or run `docker compose run --rm stalwart-init`."})
	}
	bl = append(bl, stats, lock,
		Block{Kind: "card", Title: "Guided scenarios", Icon: "wand-sparkles", Text: "Multi-step flows with explanations and live checks.", Links: scenarioLinks()},
		Block{Kind: "card", Title: "Surface", Icon: "map", KV: [][2]string{
			{"Stalwart", c.SW.BaseURL}, {"Schema", fmt.Sprintf("%d objects, %d console views", len(c.Schema.Objects), len(c.Schema.Views))},
			{"Authfly admin API", c.AuthflyURL}, {"Domain", c.Domain}, {"Session", "8 h, SameSite=Strict, CSRF on every form"},
		}})
	c.show(w, r, 200, c.page(r, "Dashboard", "Stalwart and Authfly at a glance.", "/", bl...))
}

func scenarioLinks() []Link {
	return []Link{
		{Label: "Onboard an application", Href: "/scenarios/onboard", Icon: "rocket", Text: "Create a user, register an OIDC client and run a real test sign-in, in one guided flow."},
		{Label: "GDPR request", Href: "/gdpr", Icon: "file-lock", Text: "Export or erase everything about a person, with verification in Stalwart."},
		{Label: "Lock-down check", Href: "/", Icon: "shield-check", Text: "Verify that the web UI is off and OIDC registration is locked."},
	}
}

func (c *Console) lockdownChecks(ctx context.Context) []Step {
	var st []Step
	if o, err := c.getOne(ctx, "x:OidcProvider", "singleton"); err == nil {
		st = append(st, boolStep("Anonymous OIDC client registration is off", o["anonymousClientRegistration"] == false, "x:OidcProvider.anonymousClientRegistration"))
		st = append(st, boolStep("Only registered OIDC clients are accepted", o["requireClientRegistration"] == true, "x:OidcProvider.requireClientRegistration"))
	} else {
		st = append(st, Step{"OIDC provider", "fail", err.Error()})
	}
	if apps, _, err := c.list(ctx, c.Schema.Views["x:Application"], 20, nil); err == nil && c.Schema.Views["x:Application"] != nil {
		for _, a := range apps {
			st = append(st, boolStep(fmt.Sprintf("Web app %s is disabled", cell(a["urlPrefix"])), a["enabled"] == false, "x:Application"))
		}
	}
	if d, err := c.getOne(ctx, "x:DataRetention", "singleton"); err == nil {
		st = append(st, boolStep("Deleted accounts are not archived (erasure is final)", d["archiveDeletedAccountsFor"] == nil, "x:DataRetention.archiveDeletedAccountsFor"))
	}
	ok := c.authflyPing(ctx)
	st = append(st, boolStep("Authfly internal admin API reachable", ok, c.AuthflyURL))
	return st
}

func boolStep(title string, ok bool, detail string) Step {
	if ok {
		return Step{title, "ok", detail}
	}
	return Step{title, "fail", detail}
}

// ---- generic object pages (schema-driven)

func (c *Console) view(r *http.Request) *View {
	return c.Schema.Views[r.URL.Query().Get("v")]
}

func (c *Console) objectIntro(v *View) []Block {
	n := noteFor(v)
	kv := [][2]string{{"Object", v.Name}, {"Kind", v.Kind}, {"Permissions", v.Permission + "Get / Query / Create / Update / Destroy"}}
	if v.Enterprise {
		kv = append(kv, [2]string{"Edition", "Enterprise only"})
	}
	bl := []Block{{Kind: "card", Title: "About", Icon: "info", Text: v.Desc, KV: kv, Items: n.Effects}}
	var deps []string
	for _, d := range c.Schema.Uses(v) {
		deps = append(deps, fmt.Sprintf("%s → %s", d.Field, trimX(d.Object)))
	}
	for _, d := range c.Schema.UsedBy(v) {
		deps = append(deps, fmt.Sprintf("%s.%s references this", trimX(d.Object), d.Field))
	}
	deps = append(n.Depends, deps...)
	if len(deps) > 0 {
		bl = append(bl, Block{Kind: "card", Title: "Dependencies", Icon: "git-fork", Text: "Settings this object relies on, and the objects that rely on it.", Items: deps})
	}
	if n.GDPR != "" {
		bl = append(bl, Block{Kind: "alert", Tone: "warning", Icon: "file-lock", Title: "Personal data", Text: n.GDPR})
	}
	return bl
}

func (c *Console) objectPage(w http.ResponseWriter, r *http.Request) {
	v := c.view(r)
	if v == nil {
		c.show(w, r, 404, c.page(r, "Not found", "", "", Block{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: "Unknown object", Text: r.URL.Query().Get("v")}))
		return
	}
	href := "/object?v=" + v.Name
	if v.Kind == "singleton" {
		c.objectForm(w, r, v, "singleton", nil, 200)
		return
	}
	ctx := r.Context()
	lst := c.Schema.Lists[v.Name]
	if len(lst.Columns) == 0 {
		lst = c.Schema.Lists[v.Object]
	}
	var cols []string
	var names []string
	for _, col := range lst.Columns {
		cols = append(cols, col.Label)
		names = append(names, col.Name)
	}
	if len(names) == 0 {
		for _, f := range c.Schema.FormFields(v) {
			if len(names) == 4 {
				break
			}
			if f.Kind != "json" {
				names = append(names, f.Name)
				cols = append(cols, f.Label)
			}
		}
	}
	bl := c.objectIntro(v)
	items, total, err := c.list(ctx, v, 100, append([]string{"id"}, names...))
	if err != nil {
		bl = append(bl, restrictedBlock(v, err))
	} else {
		t := &Table{Cols: append([]string{"Id"}, cols...), Empty: "Nothing here yet."}
		for _, o := range items {
			row := Row{Cells: []string{fmt.Sprint(o["id"])}, Href: "/object/edit?v=" + q(v.Name) + "&id=" + q(fmt.Sprint(o["id"]))}
			for _, n := range names {
				row.Cells = append(row.Cells, cell(o[n]))
			}
			t.Rows = append(t.Rows, row)
		}
		bl = append(bl, Block{Kind: "table", Title: nonEmpty(lst.Title, v.Label), Badge: fmt.Sprint(total), Text: lst.Subtitle, Table: t})
	}
	f := c.formFor(ctx, v, nil, true)
	f.ID, f.Action, f.Submit = "create", "/object/save", "Create "+nonEmpty(lst.SingularName, trimX(v.Label))
	f.Hidden = [][2]string{{"v", v.Name}}
	bl = append(bl, Block{Kind: "form", Title: "New " + nonEmpty(lst.SingularName, trimX(v.Label)), Icon: "plus", Text: "Validated against the schema before it is sent. " + methodHelp["set"], Form: &f},
		Block{Kind: "links", Title: "Raw API", Icon: "braces", Links: []Link{
			{Label: v.Object + "/query", Href: "/explorer?v=" + q(v.Name) + "&m=query", Icon: "search", Text: methodHelp["query"]},
			{Label: v.Object + "/get", Href: "/explorer?v=" + q(v.Name) + "&m=get", Icon: "file-search", Text: methodHelp["get"]},
			{Label: v.Object + "/set", Href: "/explorer?v=" + q(v.Name) + "&m=set", Icon: "pencil", Text: methodHelp["set"]},
		}})
	p := c.page(r, v.Label, v.Desc, href, bl...)
	p.Crumbs = []Link{{Label: v.Group, Href: href}}
	c.show(w, r, 200, p)
}

func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case float64:
		return fmt.Sprint(x)
	case map[string]any:
		if t, ok := x["@type"].(string); ok {
			return t
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return strings.Join(keys, ", ")
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// formFor builds the schema-driven form; refs are prefilled from live data, values from the current object.
func (c *Console) formFor(ctx context.Context, v *View, cur map[string]any, create bool) FormVM {
	var fields []Field
	defs := c.Schema.Fields[v.Schema].Defaults
	for _, f := range c.Schema.FormFields(v) {
		if f.Enterprise {
			continue
		}
		if create && f.Kind == "readonly" {
			continue
		}
		if !create && f.Update == "immutable" {
			f.Kind = "readonly"
		}
		if f.Kind == "ref" {
			f.Options = c.options(ctx, f.Ref)
		}
		switch {
		case cur != nil:
			f.Value = f.Display(cur[f.Name])
		case defs[f.Name] != nil:
			f.Value = f.Display(defs[f.Name])
		}
		if f.Name == "credentials" || f.Kind == "password" {
			if !create {
				f.Kind, f.Value = "password", ""
				f.Desc = "Leave empty to keep the current value. " + f.Desc
			}
			if f.Name == "credentials" {
				f.Kind, f.Required = "password", create && v.Object == "x:Account" && v.Variant == "User"
				f.Desc = "Password (sent as a Password credential). " + strings.TrimPrefix(f.Desc, "Leave empty to keep the current value. ")
				if !create {
					f.Desc = "Leave empty to keep the current password."
				}
			}
		}
		fields = append(fields, f)
	}
	return FormVM{Fields: fields}
}

func (c *Console) objectEdit(w http.ResponseWriter, r *http.Request) {
	v := c.view(r)
	if v == nil {
		http.NotFound(w, r)
		return
	}
	cur, err := c.getOne(r.Context(), v.Object, r.URL.Query().Get("id"))
	if err != nil {
		c.show(w, r, 404, c.page(r, v.Label, "", "/object?v="+v.Name, errBlock("Not found", err)))
		return
	}
	c.objectForm(w, r, v, r.URL.Query().Get("id"), cur, 200)
}

func (c *Console) objectForm(w http.ResponseWriter, r *http.Request, v *View, id string, cur map[string]any, status int, extra ...Block) {
	ctx := r.Context()
	if cur == nil && id == "singleton" {
		var err error
		if cur, err = c.getOne(ctx, v.Object, "singleton"); err != nil {
			extra = append(extra, restrictedBlock(v, err))
		}
	}
	f := c.formFor(ctx, v, cur, false)
	f.ID, f.Action, f.Submit = "edit", "/object/save", "Save changes"
	f.Hidden = [][2]string{{"v", v.Name}, {"id", id}}
	f.Note = "Only the fields you change are sent (JMAP patch)."
	bl := append(extra, c.objectIntro(v)...)
	bl = append(bl, Block{Kind: "form", Title: "Edit", Icon: "pencil", Text: fmt.Sprintf("%s %s", trimX(v.Object), id), Form: &f})
	if id != "singleton" {
		n := noteFor(v)
		bl = append(bl, Block{Kind: "form", Title: "Delete", Icon: "trash-2", Tone: "destructive", Text: nonEmpty(n.Danger, "Deleting cannot be undone."),
			Form: &FormVM{ID: "destroy", Action: "/object/destroy", Submit: "Delete…", Variant: "destructive", Hidden: [][2]string{{"v", v.Name}, {"id", id}}}})
	}
	bl = append(bl, Block{Kind: "code", Title: "Current value", Icon: "braces", Code: jsonPretty(redact(cur))})
	p := c.page(r, v.Label+" "+id, v.Desc, "/object?v="+v.Name, bl...)
	p.Crumbs = []Link{{Label: v.Group, Href: "/object?v=" + v.Name}, {Label: v.Label, Href: "/object?v=" + v.Name}}
	c.show(w, r, status, p)
}

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "secret") || strings.Contains(kl, "password") || kl == "credentials" || strings.Contains(kl, "privatekey") {
				out[k] = "•••"
				continue
			}
			out[k] = redact(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = redact(x[i])
		}
		return out
	}
	return v
}

func (c *Console) objectSave(w http.ResponseWriter, r *http.Request) {
	v := c.Schema.Views[r.PostFormValue("v")]
	if v == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	id := r.PostFormValue("id")
	create := id == ""
	var cur map[string]any
	if !create {
		cur, _ = c.getOne(ctx, v.Object, id)
	}
	form := c.formFor(ctx, v, cur, create)
	patch := map[string]any{}
	bad := 0
	for i := range form.Fields {
		f := &form.Fields[i]
		raw := r.PostFormValue(f.Name)
		_, present := r.PostForm[f.Name]
		if f.Kind == "readonly" {
			continue
		}
		if f.Name == "credentials" {
			if raw != "" {
				if len(raw) < 10 {
					f.Err, bad = "at least 10 characters", bad+1
				}
				patch["credentials"] = map[string]any{"0": map[string]any{"@type": "Password", "secret": raw}}
			} else if f.Required {
				f.Err, bad = "a password is required", bad+1
			}
			continue
		}
		if f.Kind == "password" && raw == "" && !create {
			continue
		}
		val, send, err := f.Parse(raw, present)
		f.Value = raw
		if err != nil {
			f.Err = err.Error()
			bad++
			continue
		}
		if !send {
			continue
		}
		if !create && jsonEq(val, cur[f.Name]) {
			continue
		}
		patch[f.Name] = val
	}
	if bad > 0 {
		form.ID, form.Action, form.Submit = "edit", "/object/save", "Save"
		form.Hidden = [][2]string{{"v", v.Name}, {"id", id}}
		bl := []Block{{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: fmt.Sprintf("%d field(s) need attention", bad), Text: "Nothing was sent to Stalwart."},
			{Kind: "form", Title: map[bool]string{true: "New " + trimX(v.Label), false: "Edit"}[create], Icon: "pencil", Form: &form}}
		c.show(w, r, 422, c.page(r, v.Label, v.Desc, "/object?v="+v.Name, bl...))
		return
	}
	args := map[string]any{}
	if create {
		if v.Variant != "" {
			patch["@type"] = v.Variant
		}
		args["create"] = map[string]any{"new": patch}
	} else {
		if len(patch) == 0 {
			c.objectForm(w, r, v, id, cur, 200, Block{Kind: "alert", Icon: "info", Title: "No changes", Text: "Nothing was sent."})
			return
		}
		args["update"] = map[string]any{id: patch}
	}
	body, _ := json.MarshalIndent(map[string]any{"using": []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}, "methodCalls": []any{[]any{v.Object + "/set", redact(args), "0"}}}, "", "  ")
	out, err := c.call(ctx, v.Object+"/set", args)
	var newID string
	if err == nil {
		newID, err = setResult(out)
	}
	op := map[bool]string{true: "create", false: "update"}[create]
	c.invalidate()
	if err != nil {
		c.log(r, "object."+op, v.Name, "error", map[string]string{"id": id, "error": err.Error()})
		bl := []Block{errBlock("Stalwart refused the change", err), {Kind: "code", Title: "Request", Code: string(body)}}
		c.show(w, r, 400, c.page(r, v.Label, v.Desc, "/object?v="+v.Name, bl...))
		return
	}
	if create {
		id = newID
	}
	c.log(r, "object."+op, v.Name, "ok", map[string]string{"id": id, "fields": strings.Join(keys(patch), ",")})
	done := Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: map[bool]string{true: "Created", false: "Saved"}[create], Text: fmt.Sprintf("%s %s: %s", trimX(v.Object), id, strings.Join(keys(patch), ", "))}
	resp := Block{Kind: "code", Title: "Response", Icon: "braces", Code: jsonPretty(out)}
	if v.Kind == "singleton" || id == "" {
		c.objectForm(w, r, v, nonEmpty(id, "singleton"), nil, 200, done, resp)
		return
	}
	cur, _ = c.getOne(ctx, v.Object, id)
	c.objectForm(w, r, v, id, cur, 200, done, resp)
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y) || (a == nil && b == nil)
}

// objectDestroy asks for a typed confirmation first (destructive action), then destroys.
func (c *Console) objectDestroy(w http.ResponseWriter, r *http.Request) {
	v := c.Schema.Views[r.PostFormValue("v")]
	id := r.PostFormValue("id")
	if v == nil || id == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	cur, err := c.getOne(ctx, v.Object, id)
	if err != nil {
		c.show(w, r, 404, c.page(r, v.Label, "", "/object?v="+v.Name, errBlock("Not found", err)))
		return
	}
	label := labelOf(c.Schema, v, cur)
	if r.PostFormValue("confirm") != label {
		c.confirm(w, r, "Delete "+trimX(v.Object)+" "+label, c.dangerItems(v, cur), "/object/destroy", [][2]string{{"v", v.Name}, {"id", id}}, label, r.PostFormValue("confirm") != "")
		return
	}
	out, err := c.call(ctx, v.Object+"/set", map[string]any{"destroy": []string{id}})
	if err == nil {
		_, err = setResult(out)
	}
	c.invalidate()
	if err != nil {
		c.log(r, "object.destroy", v.Name, "error", map[string]string{"id": id, "error": err.Error()})
		c.show(w, r, 400, c.page(r, v.Label, "", "/object?v="+v.Name, errBlock("Stalwart refused the deletion", err)))
		return
	}
	c.log(r, "object.destroy", v.Name, "ok", map[string]string{"id": id, "label": label})
	c.show(w, r, 200, c.page(r, v.Label, "", "/object?v="+v.Name,
		Block{Kind: "alert", Tone: "success", Icon: "circle-check", Title: "Deleted", Text: fmt.Sprintf("%s %s (%s) was deleted.", trimX(v.Object), id, label)},
		Block{Kind: "links", Links: []Link{{Label: "Back to " + v.Label, Href: "/object?v=" + v.Name, Icon: "arrow-left"}}}))
}

func (c *Console) dangerItems(v *View, cur map[string]any) []string {
	n := noteFor(v)
	items := []string{"This cannot be undone."}
	if n.Danger != "" {
		items = append(items, n.Danger)
	}
	for _, d := range c.Schema.UsedBy(v) {
		items = append(items, fmt.Sprintf("%s.%s may reference it", trimX(d.Object), d.Field))
		if len(items) > 8 {
			break
		}
	}
	if n.GDPR != "" {
		items = append(items, n.GDPR)
	}
	return items
}

// confirm renders the typed-confirmation step of a destructive or GDPR action.
func (c *Console) confirm(w http.ResponseWriter, r *http.Request, title string, items []string, action string, hidden [][2]string, expect string, mismatch bool) {
	f := FormVM{ID: "confirm", Action: action, Submit: "I understand, continue", Variant: "destructive", Hidden: hidden,
		Fields: []Field{{Name: "confirm", Label: "Type " + expect + " to confirm", Kind: "text", Required: true}}}
	if mismatch {
		f.Fields[0].Err = "The text does not match."
	}
	bl := []Block{{Kind: "alert", Tone: "destructive", Icon: "triangle-alert", Title: "Destructive action", Items: items}, {Kind: "form", Title: title, Icon: "shield-alert", Form: &f}}
	c.show(w, r, map[bool]int{true: 422, false: 200}[mismatch], c.page(r, title, "Confirm before anything changes.", "", bl...))
}

var _ = time.Second

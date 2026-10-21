package main

// Request builder: a JMAP request per object and method, prefilled with a schema-derived template, sent as the
// console admin; shows the response, a curl export, and keeps named saved requests (CONSOLE_DATA/saved.json).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Saved struct {
	Name, View, Method, Body, Time string
}

func (c *Console) savedPath() string { return filepath.Join(c.Data, "saved.json") }

func (c *Console) loadSaved() []Saved {
	var s []Saved
	b, _ := os.ReadFile(c.savedPath())
	_ = json.Unmarshal(b, &s)
	return s
}

func (c *Console) storeSaved(s []Saved) {
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(c.savedPath()+".tmp", b, 0o600)
	_ = os.Rename(c.savedPath()+".tmp", c.savedPath())
}

func (c *Console) template(v *View, m string) string {
	var call []any
	switch m {
	case "get":
		ids := any([]string{"singleton"})
		if v.Kind != "singleton" {
			ids = nil
		}
		call = []any{v.Object + "/get", map[string]any{"ids": ids}, "0"}
	case "query":
		args := map[string]any{"limit": 10, "calculateTotal": true}
		if v.Variant != "" {
			args["filter"] = map[string]any{"@type": v.Variant}
		}
		call = []any{v.Object + "/query", args, "0"}
	case "changes":
		call = []any{v.Object + "/changes", map[string]any{"sinceState": "n"}, "0"}
	default:
		sample := map[string]any{}
		if v.Variant != "" {
			sample["@type"] = v.Variant
		}
		for _, f := range c.Schema.FormFields(v) {
			if f.Required && f.Kind != "readonly" {
				sample[f.Name] = sampleValue(f)
			}
		}
		if v.Kind == "singleton" {
			call = []any{v.Object + "/set", map[string]any{"update": map[string]any{"singleton": map[string]any{}}}, "0"}
		} else {
			call = []any{v.Object + "/set", map[string]any{"create": map[string]any{"new": sample}}, "0"}
		}
	}
	b, _ := json.MarshalIndent(map[string]any{"using": []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}, "methodCalls": []any{call}}, "", "  ")
	return string(b)
}

func sampleValue(f Field) any {
	switch f.Kind {
	case "number":
		return 0
	case "bool":
		return false
	case "enum", "ref":
		if len(f.Options) > 0 {
			return f.Options[0].Name
		}
		return ""
	case "json":
		return map[string]any{}
	}
	return ""
}

func (c *Console) explorerForm(r *http.Request, viewName, method, body string) []Block {
	v := c.Schema.Views[viewName]
	var views []EnumItem
	for name, w := range c.Schema.Views {
		views = append(views, EnumItem{Name: name, Label: trimX(name) + " (" + w.Kind + ")"})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Label < views[j].Label })
	methods := []EnumItem{{"query", "query"}, {"get", "get"}, {"set", "set"}, {"changes", "changes"}}
	pick := FormVM{ID: "pick", Action: "/explorer", Submit: "Load template", Variant: "outline", Inline: true, Hidden: [][2]string{{"op", "template"}},
		Fields: []Field{{Name: "v", Label: "Object", Kind: "select", Value: viewName, Options: views, Required: true}, {Name: "m", Label: "Method", Kind: "select", Value: method, Options: methods, Required: true}}}
	bl := []Block{{Kind: "form", Title: "Endpoint", Icon: "list-tree", Text: "Pick an object and a method; the body is generated from the live schema.", Form: &pick}}
	if v != nil {
		if body == "" {
			body = c.template(v, method)
		}
		help := []string{methodHelp[method]}
		n := noteFor(v)
		if method == "set" {
			help = append(help, n.Effects...)
			if n.Danger != "" {
				help = append(help, "On destroy: "+n.Danger)
			}
		}
		help = append(help, fmt.Sprintf("Required permission: %s%s", v.Permission, map[string]string{"get": "Get", "query": "Query", "changes": "Get", "set": "Create/Update/Destroy"}[method]))
		bl = append(bl, Block{Kind: "card", Title: v.Object + "/" + method, Icon: "info", Text: v.Desc, Items: help})
		send := FormVM{ID: "send", Action: "/explorer", Submit: "Send request", Hidden: [][2]string{{"op", "send"}, {"v", viewName}, {"m", method}},
			Fields: []Field{{Name: "body", Label: "JMAP request (POST /jmap)", Kind: "textarea", Value: body, Desc: "Validated as JSON and checked against the object before sending. Destructive calls ask for confirmation."}}}
		bl = append(bl, Block{Kind: "form", Title: "Request", Icon: "send", Form: &send})
	}
	return bl
}

func (c *Console) savedBlock() Block {
	saved := c.loadSaved()
	t := &Table{Cols: []string{"Name", "Endpoint", "Saved"}, Empty: "No saved requests yet. Send a request, then save it."}
	var forms []FormVM
	for i, s := range saved {
		t.Rows = append(t.Rows, Row{Cells: []string{s.Name, s.View + " " + s.Method, s.Time}, Href: fmt.Sprintf("/explorer?saved=%d", i)})
		forms = append(forms, FormVM{ID: fmt.Sprintf("del-%d", i), Action: "/explorer/delete", Submit: "Delete " + s.Name, Variant: "outline", Hidden: [][2]string{{"i", fmt.Sprint(i)}}})
	}
	return Block{Kind: "table", Title: "Saved requests", Icon: "bookmark", Table: t, Forms: forms}
}

func (c *Console) explorerPage(w http.ResponseWriter, r *http.Request) {
	viewName, method, body := r.URL.Query().Get("v"), nonEmpty(r.URL.Query().Get("m"), "query"), ""
	if s := r.URL.Query().Get("saved"); s != "" {
		saved := c.loadSaved()
		var i int
		fmt.Sscan(s, &i)
		if i >= 0 && i < len(saved) {
			viewName, method, body = saved[i].View, saved[i].Method, saved[i].Body
		}
	}
	if viewName == "" {
		viewName = "x:Account/User"
	}
	bl := append(c.explorerForm(r, viewName, method, body), c.savedBlock())
	c.show(w, r, 200, c.page(r, "Request builder", "Every management object, every method, with live schema templates.", "/explorer", bl...))
}

func (c *Console) explorerSend(w http.ResponseWriter, r *http.Request) {
	viewName, method, body := r.PostFormValue("v"), r.PostFormValue("m"), r.PostFormValue("body")
	if r.PostFormValue("op") != "send" {
		http.Redirect(w, r, "/explorer?v="+q(viewName)+"&m="+q(method), http.StatusSeeOther)
		return
	}
	var req struct {
		Using       []string `json:"using"`
		MethodCalls [][]any  `json:"methodCalls"`
	}
	var problems []string
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		problems = append(problems, "Body is not valid JSON: "+err.Error())
	} else {
		if len(req.MethodCalls) == 0 {
			problems = append(problems, "methodCalls is empty")
		}
		if !contains(req.Using, "urn:stalwart:jmap") {
			problems = append(problems, `using must include "urn:stalwart:jmap" for x: objects`)
		}
		for _, mc := range req.MethodCalls {
			if len(mc) != 3 {
				problems = append(problems, "each method call is [name, arguments, callId]")
				continue
			}
			name, _ := mc[0].(string)
			obj, _, _ := strings.Cut(name, "/")
			if _, ok := c.Schema.Objects[obj]; !ok && strings.HasPrefix(obj, "x:") {
				problems = append(problems, "unknown object "+obj)
			}
		}
	}
	destructive := strings.Contains(body, `"destroy"`)
	if len(problems) == 0 && destructive && r.PostFormValue("confirm") != "destroy" {
		c.confirm(w, r, "Send a destroy request", []string{"The request destroys objects. This cannot be undone.", "Check the ids in the body before you continue."},
			"/explorer", [][2]string{{"op", "send"}, {"v", viewName}, {"m", method}, {"body", body}}, "destroy", r.PostFormValue("confirm") != "")
		return
	}
	bl := c.explorerForm(r, viewName, method, body)
	if len(problems) > 0 {
		bl = append([]Block{{Kind: "alert", Tone: "destructive", Icon: "circle-x", Title: "Not sent", Items: problems}}, bl...)
		c.show(w, r, 422, c.page(r, "Request builder", "", "/explorer", append(bl, c.savedBlock())...))
		return
	}
	start := time.Now()
	code, resp, err := c.SW.Raw(r.Context(), "POST", "/jmap", []byte(body), "application/json")
	elapsed := time.Since(start)
	c.invalidate()
	outcome := "ok"
	if err != nil || code >= 400 || strings.Contains(string(resp), `"error"`) {
		outcome = "error"
	}
	c.log(r, "explorer.send", viewName, outcome, map[string]string{"method": method, "status": fmt.Sprint(code), "destructive": fmt.Sprint(destructive)})
	pretty := string(resp)
	var anyv any
	if json.Unmarshal(resp, &anyv) == nil {
		pretty = jsonPretty(redact(anyv))
	}
	if err != nil {
		pretty = err.Error()
	}
	res := Block{Kind: "code", Title: fmt.Sprintf("Response: HTTP %d in %d ms", code, elapsed.Milliseconds()), Icon: "inbox", Code: pretty}
	save := FormVM{ID: "save", Action: "/explorer/save", Submit: "Save request", Variant: "outline", Inline: true, Hidden: [][2]string{{"v", viewName}, {"m", method}, {"body", body}},
		Fields: []Field{{Name: "name", Label: "Name", Kind: "text", Required: true, Value: viewName + " " + method}}}
	bl = append(bl, res, Block{Kind: "code", Title: "curl", Icon: "terminal", Text: "Reproduce from a shell on the host (through the tunnel, Stalwart is on 127.0.0.1:8080).", Code: c.curl("/jmap", []byte(body))},
		Block{Kind: "form", Title: "Save", Icon: "bookmark", Form: &save}, c.savedBlock())
	c.show(w, r, 200, c.page(r, "Request builder", "", "/explorer", bl...))
}

func (c *Console) explorerSave(w http.ResponseWriter, r *http.Request) {
	s := append(c.loadSaved(), Saved{Name: strings.TrimSpace(r.PostFormValue("name")), View: r.PostFormValue("v"), Method: r.PostFormValue("m"), Body: r.PostFormValue("body"), Time: time.Now().UTC().Format("2006-01-02 15:04 UTC")})
	c.storeSaved(s)
	c.log(r, "explorer.save", r.PostFormValue("v"), "ok", map[string]string{"name": r.PostFormValue("name")})
	http.Redirect(w, r, "/explorer?saved="+fmt.Sprint(len(s)-1), http.StatusSeeOther)
}

func (c *Console) explorerDelete(w http.ResponseWriter, r *http.Request) {
	s := c.loadSaved()
	var i int
	fmt.Sscan(r.PostFormValue("i"), &i)
	if i >= 0 && i < len(s) {
		c.log(r, "explorer.delete", s[i].View, "ok", map[string]string{"name": s[i].Name})
		s = append(s[:i], s[i+1:]...)
		c.storeSaved(s)
	}
	http.Redirect(w, r, "/explorer", http.StatusSeeOther)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

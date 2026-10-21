package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// call runs one JMAP method as the console's Stalwart admin and returns its arguments (a JMAP error becomes an error).
func (c *Console) call(ctx context.Context, method string, args map[string]any) (map[string]any, error) {
	r, err := c.SW.JMAP(ctx, []any{method, args, "0"})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(r[0][1], &out)
	return out, nil
}

// list returns up to limit objects of a view (query + get), filtered to the view's variant.
func (c *Console) list(ctx context.Context, v *View, limit int, props []string) ([]map[string]any, int, error) {
	q := map[string]any{"limit": limit, "calculateTotal": true}
	if v.Variant != "" {
		q["filter"] = map[string]any{"@type": v.Variant}
	}
	g := map[string]any{"#ids": map[string]any{"resultOf": "q", "name": v.Object + "/query", "path": "/ids"}}
	if props != nil {
		g["properties"] = append(props, "@type")
	}
	r, err := c.SW.JMAP(ctx, []any{v.Object + "/query", q, "q"}, []any{v.Object + "/get", g, "g"})
	if err != nil && q["filter"] != nil { // the filter is a convenience; fall back to client-side filtering
		delete(q, "filter")
		r, err = c.SW.JMAP(ctx, []any{v.Object + "/query", q, "q"}, []any{v.Object + "/get", g, "g"})
	}
	if err != nil {
		return nil, 0, err
	}
	var qr struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(r[0][1], &qr)
	var gr struct {
		List []map[string]any `json:"list"`
	}
	_ = json.Unmarshal(r[1][1], &gr)
	var out []map[string]any
	for _, o := range gr.List {
		if v.Variant != "" && o["@type"] != nil && o["@type"] != v.Variant {
			continue
		}
		out = append(out, o)
	}
	return out, qr.Total, nil
}

func (c *Console) getOne(ctx context.Context, obj, id string) (map[string]any, error) {
	out, err := c.call(ctx, obj+"/get", map[string]any{"ids": []string{id}})
	if err != nil {
		return nil, err
	}
	l, _ := out["list"].([]any)
	if len(l) == 0 {
		return nil, fmt.Errorf("%s %s not found", trimX(obj), id)
	}
	m, _ := l[0].(map[string]any)
	return m, nil
}

// options loads live choices for a reference field (prefill from live data), cached for 20 s.
func (c *Console) options(ctx context.Context, ref string) []EnumItem {
	c.mu.Lock()
	if co, ok := c.optCache[ref]; ok && time.Since(co.at) < 20*time.Second {
		c.mu.Unlock()
		return co.opts
	}
	c.mu.Unlock()
	v := c.Schema.Views[ref]
	if v == nil {
		obj, variant, _ := strings.Cut(ref, "/")
		v = &View{Name: ref, Object: obj, Variant: variant}
	}
	items, _, err := c.list(ctx, v, 500, nil)
	if err != nil {
		return nil
	}
	var opts []EnumItem
	for _, o := range items {
		opts = append(opts, EnumItem{Name: fmt.Sprint(o["id"]), Label: labelOf(c.Schema, v, o)})
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].Label < opts[j].Label })
	c.mu.Lock()
	c.optCache[ref] = cachedOpts{time.Now(), opts}
	c.mu.Unlock()
	return opts
}

func (c *Console) invalidate() {
	c.mu.Lock()
	c.optCache = map[string]cachedOpts{}
	c.mu.Unlock()
}

func labelOf(s *Schema, v *View, o map[string]any) string {
	for _, k := range []string{s.Lists[v.Name].LabelProperty, s.Lists[v.Object].LabelProperty, "emailAddress", "name", "description", "clientId"} {
		if k == "" {
			continue
		}
		if x, ok := o[k].(string); ok && x != "" {
			if k == "description" || k == "name" {
				if d, ok := o["description"].(string); ok && k == "name" && d != "" {
					return x + " (" + d + ")"
				}
			}
			return x
		}
	}
	return fmt.Sprint(o["id"])
}

// setResult checks a /set response for created/updated/destroyed and turns notX entries into errors.
func setResult(out map[string]any) (created string, err error) {
	for _, k := range []string{"notCreated", "notUpdated", "notDestroyed"} {
		if m, ok := out[k].(map[string]any); ok && len(m) > 0 {
			for _, v := range m {
				b, _ := json.Marshal(v)
				return "", fmt.Errorf("%s: %s", k, b)
			}
		}
	}
	if m, ok := out["created"].(map[string]any); ok {
		for _, v := range m {
			if o, ok := v.(map[string]any); ok {
				return fmt.Sprint(o["id"]), nil
			}
		}
	}
	return "", nil
}

// curl renders a reproducible curl command for a JMAP request (the password stays a variable).
func (c *Console) curl(path string, body []byte) string {
	return fmt.Sprintf("curl -sS -u \"%s:$STALWART_ADMIN_PASSWORD\" \\\n  -H 'Content-Type: application/json' \\\n  -X POST %s%s \\\n  --data-binary @- <<'JSON'\n%s\nJSON", c.SW.AdminUser, c.SW.BaseURL, path, string(body))
}

func q(v string) string { return url.QueryEscape(v) }

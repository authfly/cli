package main

import (
	"github.com/a-h/templ"
	"strconv"
	"strings"

	selectx "github.com/ui8kit/codegen/packages/templ/ui/ui/select"
)

func iconOr(s string) string {
	if s == "" {
		return "circle"
	}
	return s
}

func alertRole(t string) string {
	if t == "destructive" || t == "warning" {
		return "alert"
	}
	return "status"
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func trimX(s string) string { return strings.TrimPrefix(s, "x:") }

func selOpts(f Field) []selectx.SelectOptionItem {
	out := []selectx.SelectOptionItem{}
	if !f.Required || f.Value == "" {
		out = append(out, selectx.SelectOptionItem{Value: "", Label: "(none)"})
	}
	for _, o := range f.Options {
		l := o.Label
		if l == "" {
			l = o.Name
		}
		out = append(out, selectx.SelectOptionItem{Value: o.Name, Label: l})
	}
	return out
}

func mobileNav(groups []NavGroup) []selectx.SelectOptionItem {
	var out []selectx.SelectOptionItem
	for _, g := range groups {
		for _, it := range g.Items {
			out = append(out, selectx.SelectOptionItem{Value: it.View, Label: g.Title + ": " + it.Label})
		}
	}
	return out
}

func rowsFor(f Field) int {
	if n := strings.Count(f.Value, "\n") + 2; n > 4 {
		if n > 24 {
			return 24
		}
		return n
	}
	return 4
}

func jsonPlaceholder(f Field) string {
	if f.Kind != "json" {
		return ""
	}
	switch f.Type.Type {
	case "set":
		return `["value"]`
	case "map", "objectList":
		return `{"key": "value"}`
	}
	return `{"@type": "..."}`
}

func inputType(f Field) string {
	switch {
	case f.Kind == "password":
		return "password"
	case f.Kind == "number":
		return "number"
	case f.Format == "emailAddress":
		return "email"
	case f.Format == "uri":
		return "url"
	}
	return "text"
}

func placeholder(f Field) string {
	switch f.Format {
	case "duration":
		return "e.g. 30s, 15m, 7d"
	case "size":
		return "e.g. 10mb"
	case "uri":
		return "https://"
	}
	if f.Kind == "datetime" {
		return "2026-10-21T12:00:00Z"
	}
	return ""
}

func autoc(f Field) string {
	if f.Kind == "password" {
		return "new-password"
	}
	return "off"
}

func inputAttrs(f Field) templ.Attributes {
	a := templ.Attributes{"aria-describedby": "d-" + f.Name}
	if f.Type.MaxLength > 0 {
		a["maxlength"] = strconv.Itoa(f.Type.MaxLength)
	}
	if f.Type.MinLength > 0 {
		a["minlength"] = strconv.Itoa(f.Type.MinLength)
	}
	if f.Kind == "number" {
		if f.Format == "unsignedInteger" {
			a["min"] = "0"
		}
		if f.Format == "float" {
			a["step"] = "any"
		}
	}
	return a
}

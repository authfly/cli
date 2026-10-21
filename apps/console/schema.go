package main

// The console is driven by the live Stalwart schema (GET /api/schema): navigation from the web-admin layouts, a form
// per object from fields/forms, list columns from lists, enum options from enums, and the dependency graph from the
// objectId references between objects.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TypeDef struct {
	Type       string   `json:"type"`
	Format     string   `json:"format"`
	Nullable   bool     `json:"nullable"`
	ObjectName string   `json:"objectName"`
	EnumName   string   `json:"enumName"`
	MaxLength  int      `json:"maxLength"`
	MinLength  int      `json:"minLength"`
	Min        *float64 `json:"min"`
	Max        *float64 `json:"max"`
	MinItems   int      `json:"minItems"`
	Class      *TypeDef `json:"class"`
	KeyClass   *TypeDef `json:"keyClass"`
	ValueClass *TypeDef `json:"valueClass"`
}

type PropDef struct {
	Description string  `json:"description"`
	Type        TypeDef `json:"type"`
	Update      string  `json:"update"` // mutable, immutable, serverSet
	Enterprise  bool    `json:"enterprise"`
}

type FieldsDef struct {
	Properties map[string]PropDef `json:"properties"`
	Defaults   map[string]any     `json:"defaults"`
}

type FormDef struct {
	Sections []struct {
		Title  string `json:"title"`
		Fields []struct {
			Name  string `json:"name"`
			Label string `json:"label"`
		} `json:"fields"`
	} `json:"sections"`
}

type ListDef struct {
	Title         string `json:"title"`
	Subtitle      string `json:"subtitle"`
	LabelProperty string `json:"labelProperty"`
	SingularName  string `json:"singularName"`
	PluralName    string `json:"pluralName"`
	Columns       []struct {
		Name  string `json:"name"`
		Label string `json:"label"`
	} `json:"columns"`
}

type EnumItem struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

type Variant struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	SchemaName string `json:"schemaName"`
}

type SchemaDef struct {
	Type       string    `json:"type"` // single, multiple
	SchemaName string    `json:"schemaName"`
	Variants   []Variant `json:"variants"`
}

type ObjectDef struct {
	Type             string `json:"type"` // object, singleton, view
	Description      string `json:"description"`
	PermissionPrefix string `json:"permissionPrefix"`
	Enterprise       bool   `json:"enterprise"`
}

type Schema struct {
	Objects map[string]ObjectDef  `json:"objects"`
	Schemas map[string]SchemaDef  `json:"schemas"`
	Fields  map[string]FieldsDef  `json:"fields"`
	Forms   map[string]FormDef    `json:"forms"`
	Lists   map[string]ListDef    `json:"lists"`
	Enums   map[string][]EnumItem `json:"enums"`
	Layouts []json.RawMessage     `json:"layouts"`

	Nav []NavGroup `json:"-"`
	// views: "x:Account/User" -> object x:Account, variant User, fields schema x:UserAccount
	Views map[string]*View `json:"-"`
}

// View is one navigable object (a variant of a multi-schema object is a view of its own).
type View struct {
	Name       string // x:Account/User
	Object     string // x:Account
	Variant    string // User
	Schema     string // x:UserAccount (fields/forms key)
	Label      string
	Group      string
	Kind       string // object, singleton
	Desc       string
	Permission string
	Enterprise bool
}

type NavItem struct{ Label, View string }
type NavGroup struct {
	Title, Icon string
	Items       []NavItem
}

func fetchSchema(ctx context.Context, base, user, pass string) (*Schema, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		s, err := fetchSchemaOnce(ctx, base, user, pass)
		if err == nil {
			return s, nil
		}
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}

func fetchSchemaOnce(ctx context.Context, base, user, pass string) (*Schema, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/schema", nil)
	req.SetBasicAuth(user, pass)
	cl := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		r.SetBasicAuth(user, pass)
		return nil
	}}
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("schema: HTTP %d", res.StatusCode)
	}
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		if b, err = io.ReadAll(zr); err != nil {
			return nil, err
		}
	}
	var s Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	s.index()
	return &s, nil
}

type layoutNode struct {
	Name     string       `json:"name"`
	Icon     string       `json:"icon"`
	Type     string       `json:"type"`
	ViewName string       `json:"viewName"`
	Items    []layoutNode `json:"items"`
	Link     *layoutNode  `json:"link"`
	Cont     *layoutNode  `json:"container"`
}

func (s *Schema) index() {
	s.Views = map[string]*View{}
	add := func(name, label, group string) *View {
		obj, variant, _ := strings.Cut(name, "/")
		od, ok := s.Objects[obj]
		if !ok || od.Type == "view" {
			return nil
		}
		v := &View{Name: name, Object: obj, Variant: variant, Label: label, Group: group, Kind: od.Type, Desc: od.Description, Permission: od.PermissionPrefix, Enterprise: od.Enterprise}
		sd := s.Schemas[obj]
		v.Schema = sd.SchemaName
		if sd.Type == "multiple" {
			for _, va := range sd.Variants {
				if va.Name == variant || (variant == "" && v.Schema == "") {
					v.Schema = va.SchemaName
					if variant == "" {
						v.Variant = va.Name
					}
				}
			}
		}
		if v.Schema == "" {
			v.Schema = obj
		}
		if _, dup := s.Views[name]; !dup {
			s.Views[name] = v
		}
		return v
	}
	// navigation from the web-admin layouts (Management, Settings, ...)
	var walk func(n layoutNode, group string, g *NavGroup)
	walk = func(n layoutNode, group string, g *NavGroup) {
		if n.Link != nil {
			walk(*n.Link, group, g)
			return
		}
		if n.Cont != nil {
			sub := &NavGroup{Title: group + " / " + n.Cont.Name, Icon: n.Cont.Icon}
			for _, c := range n.Cont.Items {
				walk(c, group+" / "+n.Cont.Name, sub)
			}
			if len(sub.Items) > 0 {
				s.Nav = append(s.Nav, *sub)
			}
			return
		}
		if n.Type == "container" {
			sub := &NavGroup{Title: group + " / " + n.Name, Icon: n.Icon}
			for _, c := range n.Items {
				walk(c, group+" / "+n.Name, sub)
			}
			if len(sub.Items) > 0 {
				s.Nav = append(s.Nav, *sub)
			}
			return
		}
		if strings.HasPrefix(n.ViewName, "x:") {
			if v := add(n.ViewName, n.Name, group); v != nil {
				g.Items = append(g.Items, NavItem{n.Name, n.ViewName})
			}
		}
	}
	for _, raw := range s.Layouts {
		var top layoutNode
		_ = json.Unmarshal(raw, &top)
		g := &NavGroup{Title: top.Name, Icon: top.Icon}
		for _, it := range top.Items {
			walk(it, top.Name, g)
		}
		if len(g.Items) > 0 {
			s.Nav = append([]NavGroup{*g}, s.Nav...)
		}
	}
	// every other management object, so the console covers the whole surface
	var rest []NavItem
	for name, od := range s.Objects {
		if !strings.HasPrefix(name, "x:") || od.Type == "view" {
			continue
		}
		if sd := s.Schemas[name]; sd.Type == "multiple" {
			for _, va := range sd.Variants {
				if _, ok := s.Views[name+"/"+va.Name]; !ok && s.Views[name] == nil {
					if add(name+"/"+va.Name, strings.TrimPrefix(name, "x:")+" ("+va.Label+")", "Other") != nil {
						rest = append(rest, NavItem{strings.TrimPrefix(name, "x:") + " (" + va.Label + ")", name + "/" + va.Name})
					}
				}
			}
			continue
		}
		if _, ok := s.Views[name]; !ok {
			if add(name, strings.TrimPrefix(name, "x:"), "Other") != nil {
				rest = append(rest, NavItem{strings.TrimPrefix(name, "x:"), name})
			}
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Label < rest[j].Label })
	if len(rest) > 0 {
		s.Nav = append(s.Nav, NavGroup{Title: "Other objects", Icon: "boxes", Items: rest})
	}
}

// ---- fields

// Field is one form control derived from the schema.
type Field struct {
	Name, Label, Desc, Section string
	Kind                       string // text, password, number, bool, enum, ref, json, datetime, readonly
	Format                     string
	Required, Nullable         bool
	Update                     string
	Value                      string
	Options                    []EnumItem // enum and ref
	Ref                        string     // referenced object of a ref
	Err                        string
	Enterprise                 bool
	Type                       TypeDef
}

func (s *Schema) FormFields(v *View) []Field {
	fd := s.Fields[v.Schema]
	seen := map[string]bool{}
	var out []Field
	addField := func(name, label, section string) {
		p, ok := fd.Properties[name]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		f := Field{Name: name, Label: label, Desc: p.Description, Section: section, Update: p.Update, Type: p.Type, Nullable: p.Type.Nullable, Format: p.Type.Format, Enterprise: p.Enterprise}
		switch p.Type.Type {
		case "string":
			f.Kind = "text"
			if p.Type.Format == "secret" || p.Type.Format == "secretText" {
				f.Kind = "password"
			}
		case "number":
			f.Kind = "number"
			if p.Type.Format == "duration" || p.Type.Format == "size" {
				f.Kind = "text"
			}
		case "boolean":
			f.Kind = "bool"
		case "enum":
			f.Kind = "enum"
			f.Options = s.Enums[p.Type.EnumName]
		case "objectId":
			f.Kind = "ref"
			f.Ref = p.Type.ObjectName
		case "utcDateTime":
			f.Kind = "datetime"
		default:
			f.Kind = "json"
		}
		if p.Update == "serverSet" {
			f.Kind = "readonly"
		}
		f.Required = !p.Type.Nullable && (p.Type.Type == "string" && p.Type.MinLength > 0 || p.Type.Type == "objectId" || p.Type.Type == "enum" || p.Type.MinItems > 0 || name == "name")
		if _, hasDef := fd.Defaults[name]; hasDef {
			f.Required = false
		}
		out = append(out, f)
	}
	for _, sec := range s.Forms[v.Schema].Sections {
		for _, fl := range sec.Fields {
			addField(fl.Name, fl.Label, sec.Title)
		}
	}
	var restNames []string
	for n := range fd.Properties {
		if !seen[n] {
			restNames = append(restNames, n)
		}
	}
	sort.Strings(restNames)
	for _, n := range restNames {
		addField(n, n, "More")
	}
	return out
}

var (
	reEmail    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reDuration = regexp.MustCompile(`^\d+(ms|s|m|h|d|w)?$`)
	reSize     = regexp.MustCompile(`^\d+\s*(b|kb|mb|gb|tb)?$`)
)

// Parse validates one submitted value against the schema and returns the JSON value to send.
func (f *Field) Parse(raw string, present bool) (any, bool, error) {
	raw = strings.TrimSpace(raw)
	if f.Kind == "readonly" {
		return nil, false, nil
	}
	if f.Kind == "bool" {
		return present && raw != "", true, nil
	}
	if raw == "" {
		if f.Required {
			return nil, false, fmt.Errorf("%s is required", f.Label)
		}
		if f.Nullable {
			return nil, true, nil
		}
		return nil, false, nil
	}
	t := f.Type
	switch f.Kind {
	case "text", "password":
		if t.MaxLength > 0 && len(raw) > t.MaxLength {
			return nil, false, fmt.Errorf("at most %d characters", t.MaxLength)
		}
		if t.MinLength > 0 && len(raw) < t.MinLength {
			return nil, false, fmt.Errorf("at least %d characters", t.MinLength)
		}
		switch t.Format {
		case "emailAddress":
			if !reEmail.MatchString(raw) {
				return nil, false, fmt.Errorf("not an email address")
			}
		case "uri":
			if u, err := url.Parse(raw); err != nil || u.Scheme == "" {
				return nil, false, fmt.Errorf("not an absolute URI")
			}
		case "duration":
			if !reDuration.MatchString(raw) {
				return nil, false, fmt.Errorf("duration like 30s, 15m, 2h, 7d (or milliseconds)")
			}
			return durationMS(raw), true, nil
		case "size":
			if !reSize.MatchString(strings.ToLower(raw)) {
				return nil, false, fmt.Errorf("size like 1048576, 10mb, 2gb")
			}
			return sizeBytes(raw), true, nil
		}
		return raw, true, nil
	case "number":
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, false, fmt.Errorf("not a number")
		}
		if (t.Format == "unsignedInteger" || t.Format == "integer") && n != float64(int64(n)) {
			return nil, false, fmt.Errorf("must be a whole number")
		}
		if t.Format == "unsignedInteger" && n < 0 {
			return nil, false, fmt.Errorf("must not be negative")
		}
		if t.Min != nil && n < *t.Min || t.Max != nil && n > *t.Max {
			return nil, false, fmt.Errorf("out of range")
		}
		return n, true, nil
	case "enum":
		for _, o := range f.Options {
			if o.Name == raw {
				return raw, true, nil
			}
		}
		return nil, false, fmt.Errorf("not one of the allowed values")
	case "ref":
		if len(f.Options) > 0 {
			for _, o := range f.Options {
				if o.Name == raw {
					return raw, true, nil
				}
			}
			return nil, false, fmt.Errorf("no such %s", strings.TrimPrefix(f.Ref, "x:"))
		}
		return raw, true, nil
	case "datetime":
		if _, err := time.Parse(time.RFC3339, raw); err != nil {
			return nil, false, fmt.Errorf("RFC 3339 time, e.g. 2026-10-21T12:00:00Z")
		}
		return raw, true, nil
	case "json":
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, false, fmt.Errorf("invalid JSON: %v", err)
		}
		return v, true, nil
	}
	return raw, true, nil
}

func durationMS(s string) float64 {
	m := map[string]float64{"": 1, "ms": 1, "s": 1000, "m": 60000, "h": 3600000, "d": 86400000, "w": 604800000}
	i := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i < 0 {
		i = len(s)
	}
	n, _ := strconv.ParseFloat(s[:i], 64)
	return n * m[s[i:]]
}

func sizeBytes(s string) float64 {
	s = strings.ToLower(strings.ReplaceAll(s, " ", ""))
	m := map[string]float64{"": 1, "b": 1, "kb": 1 << 10, "mb": 1 << 20, "gb": 1 << 30, "tb": 1 << 40}
	i := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i < 0 {
		i = len(s)
	}
	n, _ := strconv.ParseFloat(s[:i], 64)
	return n * m[s[i:]]
}

// Display renders a stored value for a form control.
func (f *Field) Display(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return ""
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// ---- dependencies

type Dep struct{ Field, Object, Desc string }

// Uses lists the objects a view references (objectId fields, also inside sets and maps); UsedBy is the reverse.
func (s *Schema) Uses(v *View) []Dep {
	var out []Dep
	for name, p := range s.Fields[v.Schema].Properties {
		for _, t := range []*TypeDef{&p.Type, p.Type.Class, p.Type.KeyClass, p.Type.ValueClass} {
			if t != nil && t.Type == "objectId" && strings.HasPrefix(t.ObjectName, "x:") {
				out = append(out, Dep{name, t.ObjectName, p.Description})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func (s *Schema) UsedBy(v *View) []Dep {
	var out []Dep
	seen := map[string]bool{}
	for _, w := range s.Views {
		for _, d := range s.Uses(w) {
			base, _, _ := strings.Cut(d.Object, "/")
			if (d.Object == v.Name || base == v.Object) && !seen[w.Name+d.Field] {
				seen[w.Name+d.Field] = true
				out = append(out, Dep{d.Field, w.Name, d.Desc})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Object+out[i].Field < out[j].Object+out[j].Field })
	return out
}

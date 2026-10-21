package main

// View model: every console page is a list of Blocks rendered by views.templ with the ui8kit primitives.

type Link struct{ Label, Href, Text, Icon, Badge string }

type Row struct {
	Cells []string
	Href  string
}

type Table struct {
	Cols  []string
	Rows  []Row
	Empty string
}

type Step struct{ Title, Status, Detail string } // Status: ok, fail, skip, warn

type FormVM struct {
	ID, Action, Submit, Variant string // Variant: default, destructive, outline
	Hidden                      [][2]string
	Fields                      []Field
	Note                        string
	Inline                      bool
}

type Block struct {
	Kind     string // card, alert, table, form, kv, code, links, steps, grid, text
	Title    string
	Text     string
	Icon     string
	Tone     string // default, destructive, success, warning
	Badge    string
	Items    []string
	Table    *Table
	Form     *FormVM
	Forms    []FormVM
	KV       [][2]string
	Code     string
	Links    []Link
	Steps    []Step
	Children []Block
}

type PageVM struct {
	Title, Subtitle, Current string
	User, Csrf               string
	Nav                      []NavGroup
	Blocks                   []Block
	Crumbs                   []Link
}

package main

// A small Markdown reader for the docs in docs/: headings (#, ##, ###), paragraphs, bullet and numbered lists, fenced
// code, block quotes (notes), and inline code, links and bold. Plus one directive, a line `::preview <slug>`, that embeds
// the live widget preview of that slug. Enough for the docs; the site renders every node with ui8kit primitives.

import (
	"regexp"
	"strings"
)

type Inline struct {
	Kind string // text, code, strong, link
	Text string
	Href string
}

type Node struct {
	Kind  string // h1, h2, h3, p, ul, ol, code, note, preview
	Lang  string
	Text  string     // code body, preview slug, heading anchor
	Spans []Inline   // h*, p, note
	Items [][]Inline // ul, ol
}

var inlineRe = regexp.MustCompile("`([^`]+)`|\\*\\*([^*]+)\\*\\*|\\[([^\\]]+)\\]\\(([^)]+)\\)")

func inlines(s string) []Inline {
	var out []Inline
	for s != "" {
		m := inlineRe.FindStringSubmatchIndex(s)
		if m == nil {
			out = append(out, Inline{Kind: "text", Text: s})
			break
		}
		if m[0] > 0 {
			out = append(out, Inline{Kind: "text", Text: s[:m[0]]})
		}
		switch {
		case m[2] >= 0:
			out = append(out, Inline{Kind: "code", Text: s[m[2]:m[3]]})
		case m[4] >= 0:
			out = append(out, Inline{Kind: "strong", Text: s[m[4]:m[5]]})
		default:
			out = append(out, Inline{Kind: "link", Text: s[m[6]:m[7]], Href: s[m[8]:m[9]]})
		}
		s = s[m[1]:]
	}
	return out
}

var olRe = regexp.MustCompile(`^\d+\. `)

func anchor(s string) string {
	s = strings.ToLower(s)
	b := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func plain(xs []Inline) string {
	b := strings.Builder{}
	for _, x := range xs {
		b.WriteString(x.Text)
	}
	return b.String()
}

func parse(src string) []Node {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out []Node
	var para []string
	flush := func() {
		if len(para) > 0 {
			out = append(out, Node{Kind: "p", Spans: inlines(strings.Join(para, " "))})
			para = nil
		}
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "```"):
			flush()
			lang := strings.TrimPrefix(t, "```")
			var body []string
			for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
				body = append(body, lines[i])
			}
			out = append(out, Node{Kind: "code", Lang: lang, Text: strings.Join(body, "\n")})
		case t == "":
			flush()
		case strings.HasPrefix(t, "::preview "):
			flush()
			out = append(out, Node{Kind: "preview", Text: strings.TrimSpace(strings.TrimPrefix(t, "::preview "))})
		case strings.HasPrefix(t, "#"):
			flush()
			n := len(t) - len(strings.TrimLeft(t, "#"))
			if n > 3 {
				n = 3
			}
			sp := inlines(strings.TrimSpace(strings.TrimLeft(t, "#")))
			out = append(out, Node{Kind: []string{"", "h1", "h2", "h3"}[n], Spans: sp, Text: anchor(plain(sp))})
		case strings.HasPrefix(t, "> "):
			flush()
			var q []string
			for ; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), ">"); i++ {
				q = append(q, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), ">")))
			}
			i--
			out = append(out, Node{Kind: "note", Spans: inlines(strings.Join(q, " "))})
		case strings.HasPrefix(t, "- ") || olRe.MatchString(t):
			flush()
			kind := "ul"
			if olRe.MatchString(t) {
				kind = "ol"
			}
			var items [][]Inline
			var cur []string
			for ; i < len(lines); i++ {
				x := strings.TrimSpace(lines[i])
				if x == "" {
					break
				}
				if strings.HasPrefix(x, "- ") || olRe.MatchString(x) {
					if cur != nil {
						items = append(items, inlines(strings.Join(cur, " ")))
					}
					cur = []string{olRe.ReplaceAllString(strings.TrimPrefix(x, "- "), "")}
				} else {
					cur = append(cur, x)
				}
			}
			items = append(items, inlines(strings.Join(cur, " ")))
			out = append(out, Node{Kind: kind, Items: items})
		default:
			para = append(para, t)
		}
	}
	flush()
	return out
}

// Command site renders the Authfly docs (docs/*.md) and the live widget previews to static HTML with Go templ and the
// generated ui8kit templ primitives. Run from the repo root: `bun run site` (builds the CSS, then `go run ./site`).
// Output: site/dist (open site/dist/index.html, or serve the folder).
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/a-h/templ"
	"github.com/ui8kit/authfly/server/core"
	"github.com/ui8kit/authfly/server/ext"
	"github.com/ui8kit/authfly/server/web"
)

type Page struct{ Slug, Title, Blurb, File string }
type Section struct {
	Title string
	Pages []Page
}

var nav = []Section{
	{"Guide", []Page{
		{"getting-started", "Getting started", "", "docs/getting-started.md"},
		{"stalwart", "Install Stalwart", "", "docs/stalwart.md"},
		{"oidc", "Configure OIDC", "", "docs/oidc.md"},
		{"architecture", "Architecture", "", "docs/architecture.md"},
		{"security", "Security and lock-down", "", "docs/security.md"},
		{"gdpr", "GDPR", "", "docs/gdpr.md"},
		{"console", "Authfly Console", "", "docs/console.md"},
	}},
	{"Reference", []Page{
		{"widgets", "Widgets", "", "docs/widgets.md"},
		{"contract", "Form contract and API", "", "docs/contract.md"},
		{"adapters", "Adapters", "", "docs/adapters.md"},
		{"extensions", "Extensions", "", "docs/extensions.md"},
		{"codegen", "Codegen and parity", "", "docs/codegen.md"},
		{"verification", "Verified and unverified", "", "docs/verification.md"},
		{"stalwart-api", "Stalwart API audit", "", "docs/stalwart-api.md"},
	}},
	{"Runtimes", []Page{
		{"runtime-react", "React", "Vite or any bundler, BFF with @authfly/node", "docs/runtimes/react.md"},
		{"runtime-vue", "Vue", "Single-file components", "docs/runtimes/vue.md"},
		{"runtime-svelte", "Svelte", "Svelte 5 components", "docs/runtimes/svelte.md"},
		{"runtime-solid", "Solid", "Solid components", "docs/runtimes/solid.md"},
		{"runtime-templ", "templ (Go)", "The hosted pages themselves", "docs/runtimes/templ.md"},
		{"runtime-twig", "Twig (PHP)", "Symfony and plain PHP", "docs/runtimes/twig.md"},
		{"runtime-latte", "Latte (PHP)", "Nette and plain PHP", "docs/runtimes/latte.md"},
		{"runtime-jinja2", "Jinja2 (Python)", "Flask, FastAPI, Django", "docs/runtimes/jinja2.md"},
	}},
}

func navClass(on bool) string {
	if on {
		return "text-sm font-medium text-foreground"
	}
	return "text-sm text-muted-foreground hover:text-foreground"
}
func currentAttr(on bool) templ.Attributes {
	if on {
		return templ.Attributes{"aria-current": "page"}
	}
	return nil
}
func listClass(kind string) string {
	return "flex flex-col gap-2 pl-6 text-muted-foreground" // markers in site/app.css (article ul, article ol)
}
func isExternal(h string) bool { return strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") }

// links between docs: foo.md and runtimes/foo.md become the flat site pages
func relink(nodes []Node) {
	fix := func(xs []Inline) {
		for i := range xs {
			h := xs[i].Href
			if xs[i].Kind != "link" || isExternal(h) || !strings.Contains(h, ".md") {
				continue
			}
			file, frag, _ := strings.Cut(h, "#")
			base := strings.TrimSuffix(filepath.Base(file), ".md")
			if strings.Contains(file, "runtimes/") {
				base = "runtime-" + base
			}
			if frag != "" {
				frag = "#" + frag
			}
			xs[i].Href = base + ".html" + frag
		}
	}
	for i := range nodes {
		fix(nodes[i].Spans)
		for _, it := range nodes[i].Items {
			fix(it)
		}
	}
}

func write(out, name string, c templ.Component) {
	var b bytes.Buffer
	if err := c.Render(context.Background(), &b); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(out, name), b.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	out := "site/dist"
	_ = os.MkdirAll(filepath.Join(out, "assets"), 0o755)
	svc := &core.Service{Cfg: core.Config{Domain: "example.com", ProductName: "Authfly"}}
	reg := ext.Registry{Social: []ext.SocialProvider{ext.StubSocial{IDValue: "github", NameValue: "Continue with GitHub"}, ext.StubSocial{IDValue: "google", NameValue: "Continue with Google"}}}
	all := web.New(svc, reg, nil, false).Previews()
	previews := map[string]web.Preview{}
	for _, p := range all {
		previews[p.Slug] = p
	}
	var runtimes []Page
	n := 0
	for _, sec := range nav {
		for _, p := range sec.Pages {
			src, err := os.ReadFile(p.File)
			if err != nil {
				panic(err)
			}
			nodes := parse(string(src))
			relink(nodes)
			if p.Slug == "widgets" {
				write(out, p.Slug+".html", widgetsPage(nav, p, nodes, all))
			} else {
				write(out, p.Slug+".html", docPage(nav, p, nodes, previews))
			}
			if sec.Title == "Runtimes" {
				runtimes = append(runtimes, p)
			}
			n++
		}
	}
	write(out, "index.html", homePage(nav, runtimes, previews["sign-in"]))
	js, _ := os.ReadFile("server/web/assets/theme.js")
	_ = os.WriteFile(filepath.Join(out, "assets", "theme.js"), js, 0o644)
	fmt.Printf("site: %d pages + index, %d live previews -> %s\n", n, len(all), out)
}

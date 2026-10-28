package web

import (
	"context"
	"io"

	"github.com/a-h/templ"
	af "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/authkit/packages/ui/templ/ui/box"
	"github.com/authfly/authkit/packages/ui/templ/ui/button"
	"github.com/authfly/authkit/packages/ui/templ/ui/link"
	"github.com/authfly/authkit/packages/ui/templ/ui/text"
)

// Document is the HTML document skeleton. UI8Kit has no primitive for the document root.
func Document(title, locale string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		children := templ.GetChildren(ctx)
		if children == nil {
			children = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		if _, err := io.WriteString(w, "<!DOCTYPE html><html lang=\""); err != nil {
			return err
		}
		if _, err := io.WriteString(w, templ.EscapeString(locale)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/><title>"); err != nil {
			return err
		}
		if _, err := io.WriteString(w, templ.EscapeString(title)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "</title><link rel=\"stylesheet\" href=\"/assets/app.css\"/><script src=\"/assets/theme.js\"></script></head><body class=\"bg-background text-foreground\">"); err != nil {
			return err
		}
		if err := children.Render(ctx, w); err != nil {
			return err
		}
		_, err := io.WriteString(w, "</body></html>")
		return err
	})
}

func langSwitch(locale, path string) templ.Component {
	en := nest(text.Text(text.TextProps{Tag: "span", Class: "text-sm font-semibold"}), textNode("EN"))
	if locale != "en" {
		en = nest(link.Link(link.LinkProps{Href: "/auth/lang?set=en&next=" + path, Class: af.LinkSkin("text-sm")}), textNode("EN"))
	}
	ru := nest(text.Text(text.TextProps{Tag: "span", Class: "text-sm font-semibold"}), textNode("RU"))
	if locale != "ru" {
		ru = nest(link.Link(link.LinkProps{Href: "/auth/lang?set=ru&next=" + path, Class: af.LinkSkin("text-sm")}), textNode("RU"))
	}
	return nest(af.Group("2", "center", "", "", nil), many(en, ru))
}

// Page is the signed-out chrome: product header, language, theme toggle, centered widget.
func Page(product, title, locale, path string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		body := templ.GetChildren(ctx)
		if body == nil {
			body = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		brand := nest(link.Link(link.LinkProps{Href: "/", Class: "flex items-center gap-2 font-semibold"}), many(
			af.LucideIcon("shield-check", "md"),
			nest(text.Text(text.TextProps{Tag: "span"}), textNode(product)),
		))
		tools := nest(af.Group("4", "center", "", "", nil), many(langSwitch(locale, path), ThemeToggle()))
		header := nest(box.Box(box.BoxProps{Tag: "header", Class: "w-full border-b border-border"}),
			nest(box.Box(box.BoxProps{Class: "mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4"}), many(brand, tools)))
		main := nest(box.Box(box.BoxProps{Tag: "main", Class: "w-full px-4 py-12"}), body)
		return Document(title+" - "+product, locale).Render(templ.WithChildren(ctx, many(header, main)), w)
	})
}

func navLink(href, label, current string) templ.Component {
	class := af.LinkSkin("text-sm text-muted-foreground")
	aria := ""
	if current == href {
		class = af.LinkSkin("text-sm")
		aria = "page"
	}
	return nest(link.Link(link.LinkProps{Href: href, Class: class, AriaCurrent: aria}), textNode(label))
}

// PortalShell is the signed-in account chrome: header, wrapped nav (no overflow at 1024px), main.
func PortalShell(product, title, locale, path, nav, home, personal, security, apps, privacy, signout string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		body := templ.GetChildren(ctx)
		if body == nil {
			body = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		brand := nest(link.Link(link.LinkProps{Href: "/account", Class: "flex items-center gap-2 font-semibold"}), many(
			af.LucideIcon("shield-check", "md"),
			nest(text.Text(text.TextProps{Tag: "span"}), textNode(product)),
		))
		tools := nest(af.Group("4", "center", "", "", nil), many(langSwitch(locale, path), ThemeToggle()))
		header := nest(box.Box(box.BoxProps{Tag: "header", Class: "w-full border-b border-border"}),
			nest(box.Box(box.BoxProps{Class: "mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4"}), many(brand, tools)))
		navBar := nest(box.Box(box.BoxProps{Tag: "nav", Class: "w-full"}),
			nest(af.Group("4", "center", "start", "flex-wrap", af.A("aria-label", "Account")), many(
				navLink("/account", home, nav),
				navLink("/account/personal", personal, nav),
				navLink("/account/security", security, nav),
				navLink("/account/apps", apps, nav),
				navLink("/account/privacy", privacy, nav),
				navLink("/auth/sign-out", signout, ""),
			)))
		main := nest(box.Box(box.BoxProps{Tag: "main", Class: "w-full min-w-0"}), body)
		shell := nest(box.Box(box.BoxProps{Class: "mx-auto flex w-full max-w-6xl flex-col gap-8 px-4 py-8"}), many(navBar, main))
		return Document(title+" - "+product, locale).Render(templ.WithChildren(ctx, many(header, shell)), w)
	})
}

// ThemeToggle: the Button primitive wired by assets/theme.js.
func ThemeToggle() templ.Component {
	moon := nest(text.Text(text.TextProps{Tag: "span", Class: "dark:hidden"}), af.LucideIcon("moon", "md"))
	sun := nest(text.Text(text.TextProps{Tag: "span", Class: "hidden dark:inline"}), af.LucideIcon("sun", "md"))
	return nest(button.Button(button.ButtonProps{
		Type: "button", Class: af.ButtonSkin("ghost", "w-10 px-0"), AriaLabel: "Dark mode", AriaPressed: "false",
		Attrs: templ.Attributes{"data-ui8kit": "theme-toggle", "data-testid": "theme-toggle"},
	}), many(moon, sun))
}

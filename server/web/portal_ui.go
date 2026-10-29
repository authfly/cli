package web

import (
	"github.com/a-h/templ"
	af "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/authkit/packages/ui/templ/ui/box"
	"github.com/authfly/authkit/packages/ui/templ/ui/button"
	"github.com/authfly/authkit/packages/ui/templ/ui/disclosure"
	"github.com/authfly/authkit/packages/ui/templ/ui/link"
	"github.com/authfly/authkit/packages/ui/templ/ui/text"
)

// Cabinet building blocks (UI8Kit 3 primitives + the Authfly layer): a full-width section card, a danger card, a
// "are you sure" disclosure in front of destructive submits (no JS: native details/summary), an empty state, the
// dashboard tile.

func dangerSkin() string { return outlineDangerSkin() }

func outlineDangerSkin() string {
	return af.ButtonSkin("outline", "text-destructive inset-ring-destructive hover:bg-destructive/10 hover:text-destructive")
}

// section is a full-width card: h2 title, an optional hint and the body.
func section(testid, id, icon, title, hint string, body ...templ.Component) templ.Component {
	head := []templ.Component{nest(af.Group("2", "center", "", "", nil), many(af.LucideIcon(icon, "md"), af.Title(2, id, "", title)))}
	if hint != "" {
		head = append(head, nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(hint)))
	}
	return nest(af.Card("max-w-none mx-0", af.A("data-testid", testid, "aria-labelledby", id)), many(
		nest(af.Stack("2", "", "", "", nil), many(head...)),
		many(body...),
	))
}

// dangerSection is the red-ringed "danger zone" card.
func dangerSection(testid, id, title, hint string, body ...templ.Component) templ.Component {
	return nest(af.Card("max-w-none mx-0 inset-ring-destructive", af.A("data-testid", testid, "aria-labelledby", id)), many(
		nest(af.Stack("2", "", "", "", nil), many(
			nest(af.Group("2", "center", "", "text-destructive", nil), many(af.LucideIcon("shield-alert", "md"), af.Title(2, id, "", title))),
			nest(text.Text(text.TextProps{Class: af.TextMuted}), textNode(hint)),
		)),
		many(body...),
	))
}

// confirm hides a destructive submit behind a summary button: the first click opens the question, the second does it.
func confirm(summary, question string, danger bool, form templ.Component) templ.Component {
	cls := af.ButtonSkin("outline", "list-none cursor-pointer")
	if danger {
		cls = outlineDangerSkin() + " list-none cursor-pointer"
	}
	return nest(disclosure.Disclosure(disclosure.DisclosureProps{Class: "w-fit"}), many(
		nest(disclosure.Summary(disclosure.SummaryProps{Class: cls}), textNode(summary)),
		nest(af.Stack("2", "start", "", "mt-4 max-w-sm rounded bg-muted p-4", af.A("role", "group")), many(
			nest(text.Text(text.TextProps{Class: "text-sm text-foreground"}), textNode(question)),
			form,
		)),
	))
}

func dangerSubmit(testid, label string) templ.Component {
	return nest(button.Button(button.ButtonProps{Type: "submit", Class: dangerSkin(), Attrs: af.A("data-testid", testid)}), textNode(label))
}

// empty is the empty-state line: a muted icon and a sentence.
func empty(icon, msg string) templ.Component {
	return nest(af.Group("2", "center", "", "rounded bg-muted p-4 text-sm text-muted-foreground", af.A("data-testid", "empty")), many(af.LucideIcon(icon, "sm"), textNode(msg)))
}

// tile is a dashboard card linking to a cabinet section.
func tile(href, icon, title, lead string) templ.Component {
	return nest(link.Link(link.LinkProps{Href: href, Class: "flex items-start gap-4 rounded border border-border bg-card p-6 hover:bg-accent", Attrs: af.A("data-testid", "tile")}), many(
		af.IconBadge(icon, ""),
		nest(af.Stack("2", "start", "", "min-w-0", nil), many(
			nest(text.Text(text.TextProps{Tag: "span", Class: "font-semibold text-foreground"}), textNode(title)),
			nest(text.Text(text.TextProps{Tag: "span", Class: af.TextMuted}), textNode(lead)),
		)),
	))
}

func grid(children ...templ.Component) templ.Component {
	return nest(box.Box(box.BoxProps{Class: "grid w-full gap-4 sm:grid-cols-2"}), many(children...))
}

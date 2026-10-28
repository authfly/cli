package web

import (
	"context"
	"io"

	"github.com/a-h/templ"
)

// nest renders parent with child as its templ children.
func nest(parent, child templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return parent.Render(templ.WithChildren(ctx, child), w)
	})
}

// many renders components in order.
func many(cs ...templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		for _, c := range cs {
			if c == nil {
				continue
			}
			if err := c.Render(ctx, w); err != nil {
				return err
			}
		}
		return nil
	})
}

// textNode writes escaped text (a templ text child).
func textNode(s string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, templ.EscapeString(s))
		return err
	})
}

func rawHTML(s string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	})
}

func ptr(s string) *string { return &s }

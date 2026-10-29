package main

// Theme presets: tokens only (UI8Kit / shadcn colour tokens), so every preset follows the kit palette.

func surfaceCls(theme string) string {
	switch theme {
	case "muted":
		return "bg-muted text-foreground"
	case "contrast":
		return "bg-primary text-primary-foreground"
	}
	return "bg-background text-foreground" // light, dark (dark = the .dark token set on <html> or the preview frame)
}

func themeScope(theme string) string {
	if theme == "dark" {
		return "dark"
	}
	return ""
}

func shapeCls(shape string) string {
	switch shape {
	case "pill":
		return "rounded-full"
	case "square":
		return "rounded-none"
	}
	return "rounded-lg"
}

// linkBtnCls is a profile button: 48px tall control, full width, 16px inner padding.
func linkBtnCls(p *Profile) string {
	base := "flex h-12 w-full items-center justify-center gap-2 px-4 text-sm font-semibold shadow-sm " + shapeCls(p.Shape) + " "
	inv := p.Theme == "contrast"
	switch p.Buttons {
	case "outline":
		if inv {
			return base + "border-2 border-border bg-transparent text-primary-foreground hover:bg-background hover:text-foreground"
		}
		return base + "border-2 border-border bg-transparent text-foreground hover:bg-accent"
	case "soft":
		return base + "bg-secondary text-secondary-foreground hover:bg-accent"
	}
	if inv {
		return base + "bg-background text-foreground hover:bg-accent"
	}
	return base + "bg-primary text-primary-foreground hover:bg-accent hover:text-accent-foreground"
}

func avatarCls(p *Profile) string {
	return "h-24 w-24 shrink-0 overflow-hidden rounded-full border-4 border-border object-cover"
}

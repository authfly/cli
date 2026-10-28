module github.com/authfly/cli

go 1.27.3

require (
	github.com/a-h/templ v0.3.1070
	github.com/authfly/authkit/packages/ui/templ v0.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/authfly/authkit/packages/ui/templ => ./.deps/authkit/packages/ui/templ

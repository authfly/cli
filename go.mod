module github.com/ui8kit/authfly

go 1.26.0

require (
	github.com/a-h/templ v0.3.1070
	github.com/ui8kit/codegen/packages/templ/ui v0.0.0
)

require (
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ui8kit/codegen/packages/templ/ui => ./packages/ui/templ

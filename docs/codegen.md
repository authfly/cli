# Codegen and parity

The widgets are not hand-written per runtime. They are specified once with the authoring builder of [ui8kit/codegen](https://github.com/ui8kit/codegen) and generated for React, Svelte, Vue, Solid, templ, Twig, Latte and Jinja2.

## Sources

- `specs/authoring/authfly.ts`: the six organisms (`AuthflySignIn`, `AuthflySignUp`, `AuthflyRequest`, `AuthflyNotice`, `AuthflyConsent`, `AuthflyAccount`), built from ui8kit primitives only (Block, Stack, Group, Form, Field, Input, Button, Alert, Link, List, Badge, IconBadge, Title, Text, Checkbox, Label, Separator, LucideIcon).
- `specs/authoring/blocks-authfly.ts`: the blocks (variants, sample props, data sources) for the catalog and the parity cases.
- `specs/content/authfly.en.json`: the English texts (dictionary under `authfly`); `specs/fixtures/*.json`: sample collections.

## Generate

```sh
tools/gen-ui.sh            # build and export to packages/ui
tools/gen-ui.sh --check    # plus bun run check (all gates, parity included)
tools/gen-ui.sh --verify   # plus bun run verify (check, codex validate, typecheck, unit tests)
```

The script clones ui8kit/codegen at the commit pinned in `codegen.lock` into `.cache/codegen`, overlays the Authfly specs (`tools/overlay.py`), runs the xgen build and exports the primitives, helpers, styles and the Authfly blocks to `packages/ui/<runtime>` (`tools/export-ui.ts`). Upstream is never modified; the overlay only adds files and registers them (organisms, blocks, catalog pages, theme pages, dictionary, fixtures).

## Gates

`bun run check` in the overlaid checkout runs every codegen gate on the Authfly widgets together with the kit: props and text rules, readability limits, duplicates, the composition rules (no raw HTML tags in blocks), drift, and **parity**: templ, Solid, Twig, Jinja2 and Latte render the same DOM as React for every brick and block case, and every document passes html-validate. Svelte and Vue are typechecked (svelte-check, vue-tsc) by `bun run verify`.

## Lint

`npx ui8px@latest lint` passes on the repository (policy in `.ui8px/`, see its README for the five utilities added for the upstream templ primitives).

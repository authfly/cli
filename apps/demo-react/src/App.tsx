// The React demo: a relying party of Authfly. Signed out: a notice with "Sign in with Authfly" (OIDC + PKCE through the
// Authfly hosted sign-in on Stalwart). Signed in: the account widget. Everything is ui8kit primitives and Authfly widgets.
import { useEffect, useState } from "react";
import { Block } from "../../../.deps/authkit/packages/ui/react/src/primitives/block/block";
import { Container } from "../../../.deps/authkit/packages/ui/react/src/primitives/container/container";
import { Group } from "../../../.deps/authkit/packages/ui/react/src/primitives/group/group";
import { Inline } from "../../../.deps/authkit/packages/ui/react/src/primitives/inline/inline";
import { LinkPlain } from "../../../.deps/authkit/packages/ui/react/src/primitives/link-plain/link-plain";
import { LucideIcon } from "../../../.deps/authkit/packages/ui/react/src/primitives/lucide-icon/lucide-icon";
import { ThemeToggle } from "../../../.deps/authkit/packages/ui/react/src/primitives/themetoggle/themetoggle";
import { AuthflyAccount, AuthflyNotice } from "../../../.deps/authkit/packages/ui/react/src/authfly";

type User = { sub: string; email: string; name: string; username: string; amr: string };
const methods = [
  { id: "password", title: "Password", text: "On", icon: "key-round" },
  { id: "magic", title: "Magic link", text: "On", icon: "mail" },
  { id: "totp", title: "Authenticator app", text: "Soon", icon: "smartphone" },
  { id: "webauthn", title: "Security key", text: "Soon", icon: "key" },
];

export function App() {
  const [state, setState] = useState<{ loading: boolean; user?: User; error?: string }>({ loading: true });
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    const err = new URLSearchParams(location.search).get("error");
    fetch("/api/me").then(async (r) => setState({ loading: false, user: r.ok ? ((await r.json()) as { user: User }).user : undefined, error: err ?? undefined }));
  }, []);
  const toggle = () => {
    const d = !dark;
    document.documentElement.classList.toggle("dark", d);
    localStorage.setItem("authfly-theme", d ? "dark" : "light");
    setDark(d);
  };
  return (
    <>
      <Block Tag="header" Class="w-full border-b border-border">
        <Container Class="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4">
          <LinkPlain Href="/" Class="flex items-center gap-2 font-semibold">
            <LucideIcon Name="atom" Size={20} />
            <Inline>Demo app (React)</Inline>
          </LinkPlain>
          <Group Gap="2" Align="center">
            <ThemeToggle Variant="ghost" Size="default" Attrs={{ "aria-pressed": String(dark), onClick: toggle, "data-testid": "theme-toggle" }} />
          </Group>
        </Container>
      </Block>
      <Block Tag="main" Class="w-full px-4 py-12">
        {state.loading ? null : state.user ? (
          <AuthflyAccount id="demo" title="Your account" text="Signed in with single sign-on through Authfly." name={state.user.name || state.user.username} email={state.user.email}
            verified methods={methods} labels={{ name: "Name", email: "Email", verified: "Verified", unverified: "Not verified", security: "Sign-in methods", signout: "Sign out" }} signoutUrl="/logout" />
        ) : (
          <AuthflyNotice id="demo" title={state.error ? "Sign-in was cancelled" : "Welcome to the demo"} text={state.error ? `The provider answered: ${state.error}.` : "This app has no passwords of its own. Sign in with your mail account."}
            icon={state.error ? "shield-alert" : "log-in"} tone={state.error ? "error" : "default"} labels={{ cta: "Sign in with Authfly", ctaHref: "/login", secondary: "", secondaryHref: "" }} />
        )}
      </Block>
    </>
  );
}

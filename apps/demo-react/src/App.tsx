// The React demo: a relying party of Authfly. Signed out: a notice with "Sign in with Authfly" (OIDC + PKCE through the
// Authfly hosted sign-in on Stalwart). Signed in: the account widget. Everything is UI8Kit 3 primitives and Authfly widgets.
import { useEffect, useState } from "react";
import { Box } from "../../../.deps/authkit/packages/ui/react/src/ui/box/box";
import { Button } from "../../../.deps/authkit/packages/ui/react/src/ui/button/button";
import { Link } from "../../../.deps/authkit/packages/ui/react/src/ui/link/link";
import { Text } from "../../../.deps/authkit/packages/ui/react/src/ui/text/text";
import { AuthflyAccount, AuthflyNotice, Group, LucideIcon, buttonSkin } from "../../../.deps/authkit/packages/ui/react/src/authfly";

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
      <Box tag="header" className="w-full border-b border-border">
        <Box className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4">
          <Link href="/" className="flex items-center gap-2 font-semibold">
            <LucideIcon name="blocks" size="md" />
            <Text tag="span">Demo app (React)</Text>
          </Link>
          <Group gap="2" align="center">
            <Button type="button" className={buttonSkin("ghost", "w-10 px-0")} aria-label="Dark mode" aria-pressed={dark} onClick={toggle} data-testid="theme-toggle">
              <LucideIcon name={dark ? "sun" : "moon"} size="md" />
            </Button>
          </Group>
        </Box>
      </Box>
      <Box tag="main" className="w-full px-4 py-12">
        {state.loading ? null : state.user ? (
          <AuthflyAccount id="demo" title="Your account" text="Signed in with single sign-on through Authfly." name={state.user.name || state.user.username} email={state.user.email}
            verified methods={methods} labels={{ name: "Name", email: "Email", verified: "Verified", unverified: "Not verified", security: "Sign-in methods", signout: "Sign out" }} signoutUrl="/logout" />
        ) : (
          <AuthflyNotice id="demo" title={state.error ? "Sign-in was cancelled" : "Welcome to the demo"} text={state.error ? `The provider answered: ${state.error}.` : "This app has no passwords of its own. Sign in with your mail account."}
            icon={state.error ? "shield-alert" : "log-in"} tone={state.error ? "error" : "default"} labels={{ cta: "Sign in with Authfly", ctaHref: "/login", secondary: "", secondaryHref: "" }} />
        )}
      </Box>
    </>
  );
}

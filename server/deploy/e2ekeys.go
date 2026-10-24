//go:build authfly_e2ekeys

package deploy

import (
	"fmt"
	"os"
	"slices"
)

// TEST BUILDS ONLY (go build -tags authfly_e2ekeys): also trust the authorized_keys line in AUTHFLY_E2E_TRUSTED_KEY,
// so the release e2e can sign a channel with a throwaway key (a real YubiKey signature cannot be made on a test
// box). Release builds never have this tag; tools/release-public.sh refuses to build or publish with it.
func init() {
	k := os.Getenv("AUTHFLY_E2E_TRUSTED_KEY")
	if k == "" {
		return
	}
	trustedKeys = append(slices.Clone(TrustedKeys), k)
	fmt.Fprintln(os.Stderr, "authfly: TEST BUILD (authfly_e2ekeys): also trusting the channel key in AUTHFLY_E2E_TRUSTED_KEY")
}

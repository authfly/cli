// channelverify: checks a channel signature with the keys built into this checkout's CLI (docs/release.md#signing).
// Signing itself happens on the maintainer's machine with the YubiKey (`ssh-keygen -Y sign -n authfly-channel`).
//
//	go run ./tools/channelverify verify <channel.json> [<channel.json.sig>]   (default: <channel.json>.sig)
//	go run ./tools/channelverify allowed-signers                            allowed_signers file for ssh-keygen -Y verify
package main

import (
	"fmt"
	"os"

	"github.com/authfly/cli/server/deploy"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "channelverify: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: channelverify verify <channel.json> [<sig>] | allowed-signers")
	}
	ring, err := deploy.Keyring(deploy.ActiveTrustedKeys())
	if err != nil {
		die("%v", err)
	}
	switch os.Args[1] {
	case "allowed-signers":
		fmt.Print(deploy.AllowedSigners(ring))
	case "verify":
		if len(os.Args) < 3 {
			die("usage: channelverify verify <channel.json> [<sig>]")
		}
		file, sigf := os.Args[2], os.Args[2]+".sig"
		if len(os.Args) > 3 {
			sigf = os.Args[3]
		}
		data, err := os.ReadFile(file)
		if err != nil {
			die("%v", err)
		}
		sig, err := os.ReadFile(sigf)
		if err != nil {
			die("%v", err)
		}
		who, err := deploy.VerifyChannel(data, sig, ring)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("%s: signature OK, namespace %s, by %s\n", file, deploy.SigNamespace, who)
	default:
		die("unknown command %s", os.Args[1])
	}
}

// channelsign: release signing of channel.json (docs/release.md#signing). Maintainer tool, not shipped in the CLI.
//
//	go run ./tools/channelsign keygen <key file>                 new Ed25519 key (PKCS#8 PEM, 0600); prints id + public key
//	go run ./tools/channelsign pubkey <key file>                 prints id + public key (the TrustedKeys entry)
//	go run ./tools/channelsign sign -key <file> [-key <file>] <channel.json>   writes <channel.json>.sig
//	go run ./tools/channelsign verify <channel.json>             checks <channel.json>.sig with the keys built into the CLI
//
// The private key is never printed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/authfly/cli/server/deploy"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "channelsign: "+f+"\n", a...)
	os.Exit(1)
}

func load(p string) ed25519.PrivateKey {
	st, err := os.Stat(p)
	if err != nil {
		die("%v", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		die("%s: permissions %o, want 0600 (the release key must not be readable by others)", p, st.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		die("%v", err)
	}
	k, err := deploy.ParsePrivateKey(b)
	if err != nil {
		die("%s: %v", p, err)
	}
	return k
}

func show(pub ed25519.PublicKey) {
	fmt.Printf("key id:     %s\npublic key: %s\nTrustedKeys entry: %q: %q,\n", deploy.KeyID(pub), base64.StdEncoding.EncodeToString(pub), deploy.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
}

func main() {
	if len(os.Args) < 3 {
		die("usage: channelsign keygen|pubkey|sign|verify ... (see the source header)")
	}
	switch args := os.Args[2:]; os.Args[1] {
	case "keygen":
		p := args[0]
		if _, err := os.Stat(p); err == nil {
			die("%s exists: refusing to overwrite a key", p)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("%v", err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		os.MkdirAll(filepath.Dir(p), 0o700)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			die("%v", err)
		}
		if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
			die("%v", err)
		}
		f.Close()
		fmt.Printf("wrote %s (0600)\n", p)
		show(pub)
	case "pubkey":
		show(load(args[0]).Public().(ed25519.PublicKey))
	case "sign":
		var keys []ed25519.PrivateKey
		var file string
		for i := 0; i < len(args); i++ {
			if args[i] == "-key" && i+1 < len(args) {
				keys = append(keys, load(args[i+1]))
				i++
			} else if !strings.HasPrefix(args[i], "-") {
				file = args[i]
			} else {
				die("unknown option %s", args[i])
			}
		}
		if file == "" || len(keys) == 0 {
			die("usage: channelsign sign -key <file> [-key <file>] <channel.json>")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			die("%v", err)
		}
		sig, err := deploy.SignChannel(data, keys...)
		if err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(file+".sig", sig, 0o644); err != nil {
			die("%v", err)
		}
		ids := []string{}
		for _, k := range keys {
			ids = append(ids, deploy.KeyID(k.Public().(ed25519.PublicKey)))
		}
		fmt.Printf("signed %s -> %s.sig (key %s)\n", file, file, strings.Join(ids, ", "))
	case "verify":
		data, err := os.ReadFile(args[0])
		if err != nil {
			die("%v", err)
		}
		sig, err := os.ReadFile(args[0] + ".sig")
		if err != nil {
			die("%v", err)
		}
		ring, err := deploy.Keyring(deploy.TrustedKeys)
		if err != nil {
			die("%v", err)
		}
		id, err := deploy.VerifyChannel(data, sig, ring)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("%s: signature OK (key %s, trusted by this CLI)\n", args[0], id)
	default:
		die("unknown command %s", os.Args[1])
	}
}

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/authfly/cli/server/core"
)

func inviteCmd(args []string) {
	// The store flocks AUTHFLY_STORE.lock and reloads before every write, so this
	// is safe while `authfly serve` is running (same --store path). See docs/deploy-accounts-yself-link.md.
	if len(args) == 0 {
		die("usage: authfly invite create|list|revoke [flags]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("invite "+sub, flag.ExitOnError)
	store := fs.String("store", env("AUTHFLY_STORE", "authfly-store.json"), "path of AUTHFLY_STORE")
	switch sub {
	case "create":
		kind := fs.String("kind", core.KindUser, "user | org")
		note := fs.String("note", "", "operator memo")
		ttl := fs.String("ttl", "72h", "lifetime")
		fs.Parse(rest)
		d, err := time.ParseDuration(*ttl)
		check(err)
		st, err := core.OpenStore(*store)
		check(err)
		tok, inv, err := st.CreateInvite(*kind, *note, d)
		check(err)
		fmt.Printf("invite %s kind=%s expires=%s\n", inv.ID, inv.Kind, time.Unix(inv.Expires, 0).UTC().Format(time.RFC3339))
		fmt.Println("token (shown once):", tok)
	case "list":
		fs.Parse(rest)
		st, err := core.OpenStore(*store)
		check(err)
		now := time.Now().Unix()
		for _, inv := range st.ListInvites() {
			state := "unused"
			if inv.Used > 0 {
				state = "used"
			} else if inv.Expires < now {
				state = "expired"
			}
			fmt.Printf("%s  %-4s  %-8s  exp %s  %s\n", inv.ID, inv.Kind, state, time.Unix(inv.Expires, 0).UTC().Format(time.RFC3339), inv.Note)
		}
	case "revoke":
		fs.Parse(rest)
		if fs.NArg() != 1 {
			die("usage: authfly invite revoke [-store file] <id>")
		}
		st, err := core.OpenStore(*store)
		check(err)
		if !st.RevokeInvite(fs.Arg(0)) {
			die("invite not found")
		}
		fmt.Println("revoked", fs.Arg(0))
	default:
		fmt.Fprint(os.Stderr, "usage: authfly invite create|list|revoke\n")
		os.Exit(2)
	}
}

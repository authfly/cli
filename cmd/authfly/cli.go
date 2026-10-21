package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/authfly/cli/server/deploy"
	"golang.org/x/term"
)

const usage = `authfly — self-hosted auth + personal-data storage (Authfly + Stalwart)

Usage: npx authfly <command> [flags]      (or the authfly binary)

  init      create authfly.yaml (interactive wizard; -y with flags for non-interactive)
  deploy    deploy or converge to authfly.yaml (idempotent, re-runnable)
  status    show what runs (release, services, ports)
  doctor    audit the running install against authfly.yaml and its policy pack
  upgrade   snapshot, upgrade to the newest (or --to) release, auto-rollback on failure
  rollback  restore the snapshot taken by the last upgrade
  backup    encrypted backup (AES-256-GCM with the backup_key)
  restore   restore an encrypted backup: authfly restore <file>
  secrets   list secrets and their permissions (values are never printed)
  down      stop and remove the containers (--purge also deletes the data)
  serve     run the Authfly server (what the containers run; default without a command)
  version   print the version

Common flag: -f authfly.yaml (default ./authfly.yaml). Docs: docs/deploy.md, docs/policies.md
`

var Version = "0.3.0"

func cliMain(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	file := fs.String("f", "authfly.yaml", "path of authfly.yaml")
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version", "--version":
		fmt.Println("authfly", Version)
	case "init":
		initCmd(fs, file, args)
	case "deploy":
		fs.Parse(args)
		c := load(*file)
		fmt.Printf("authfly deploy (%s)\n", c.Path())
		check(c.Deploy())
		fmt.Println("done. Next: authfly doctor; console: ssh -L", fmt.Sprintf("%d:127.0.0.1:%d", c.Ports.Console, c.Ports.Console), "<this host>, then http://127.0.0.1:"+fmt.Sprint(c.Ports.Console))
	case "status":
		fs.Parse(args)
		c := load(*file)
		st := c.LoadState()
		fmt.Printf("instance %s on %s, release %s (previous %s), policy %s, updated %s\n", c.Name, c.Target, orDash(st.Current), orDash(st.Previous), c.Policy.Pack, st.UpdatedAt.Format("2006-01-02 15:04 MST"))
		out, err := c.Driver().Status()
		fmt.Print(out)
		check(err)
	case "doctor":
		jsonOut := fs.Bool("json", false, "JSON output")
		fs.Parse(args)
		c := load(*file)
		fs := c.Doctor()
		fail := 0
		if *jsonOut {
			json.NewEncoder(os.Stdout).Encode(fs)
		}
		for _, f := range fs {
			if f.Level == "FAIL" {
				fail++
			}
			if !*jsonOut {
				fmt.Printf("%-4s  %-10s %s\n", f.Level, f.Check, f.Note)
			}
		}
		if fail > 0 {
			fmt.Printf("\n%d check(s) failed\n", fail)
			os.Exit(1)
		}
	case "upgrade":
		to := fs.String("to", "", "release version (default: newest in the channel)")
		fs.Parse(args)
		check(load(*file).Upgrade(*to))
		fmt.Println("upgrade ok")
	case "rollback":
		fs.Parse(args)
		check(load(*file).Rollback())
		fmt.Println("rollback ok")
	case "backup":
		fs.Parse(args)
		p, err := load(*file).MakeBackup("backup")
		check(err)
		fmt.Println("backup written:", p)
	case "restore":
		fs.Parse(args)
		if fs.NArg() != 1 {
			die("usage: authfly restore [-f authfly.yaml] <backup.afbk>")
		}
		check(load(*file).RestoreBackup(fs.Arg(0)))
		fmt.Println("restore ok")
	case "secrets":
		fs.Parse(args)
		c := load(*file)
		for _, n := range deploy.SecretNames {
			st, err := os.Stat(c.SecretDir() + "/" + n)
			if err != nil {
				fmt.Printf("%-24s missing\n", n)
			} else {
				fmt.Printf("%-24s set (%o)\n", n, st.Mode().Perm())
			}
		}
		if bad := c.CheckSecretPerms(); len(bad) > 0 {
			die(strings.Join(bad, "\n"))
		}
	case "down":
		purge := fs.Bool("purge", false, "also delete the data volumes")
		fs.Parse(args)
		check(load(*file).Driver().Down(*purge))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func initCmd(fs *flag.FlagSet, file *string, args []string) {
	yes := fs.Bool("y", false, "non-interactive: take flags and defaults, no questions")
	from := fs.String("config", "", "start from this YAML file (flags still override)")
	force := fs.Bool("force", false, "overwrite an existing authfly.yaml")
	c := &deploy.Config{}
	s := func(p *string, name, help string) { fs.StringVar(p, name, "", help) }
	i := func(p *int, name, help string) { fs.IntVar(p, name, 0, help) }
	s(&c.Name, "name", "instance name")
	s(&c.Target, "target", "docker | incus")
	s(&c.App.Runtime, "runtime", strings.Join(deploy.Runtimes, " | "))
	s(&c.App.Adapter, "adapter", strings.Join(deploy.Adapters, " | "))
	s(&c.Provider, "provider", "stalwart (supabase | authjs: contract stubs, refused)")
	s(&c.Domain, "domain", "mail domain of the users")
	s(&c.PublicURL, "public-url", "public URL of Authfly (OIDC issuer)")
	s(&c.HTTP.TLS, "tls", "acme | manual | off")
	s(&c.HTTP.ACMEMail, "acme-email", "Let's Encrypt account email")
	s(&c.HTTP.CertFile, "cert", "certificate file (tls manual)")
	s(&c.HTTP.KeyFile, "key", "key file (tls manual)")
	s(&c.Mail.Hostname, "mail-hostname", "mail server hostname")
	i(&c.HTTP.Port, "http-port", "public Authfly port")
	i(&c.Mail.Ports.SMTP, "smtp-port", "")
	i(&c.Mail.Ports.Submissions, "submissions-port", "")
	i(&c.Mail.Ports.IMAPS, "imaps-port", "")
	i(&c.Ports.Management, "management-port", "localhost-only Stalwart management port")
	i(&c.Ports.Console, "console-port", "localhost-only Console port")
	s(&c.Policy.Pack, "policy", strings.Join(deploy.Policies, " | "))
	s(&c.Policy.Operator, "operator", "operator / controller legal name")
	s(&c.Policy.Contact, "contact", "privacy contact email")
	s(&c.Policy.HostCountry, "host-country", "ISO country of the server")
	s(&c.Channel.Manifest, "channel", "channel manifest URL or file")
	s(&c.Incus.Subnet, "incus-subnet", "private bridge subnet")
	s(&c.Incus.Network, "incus-network", "private bridge name")
	signin := fs.String("signin", "", "comma list: magic,password,username")
	states := fs.String("us-states", "", "comma list of US states in scope (us-pii)")
	clients := fs.String("client", "", "OIDC client: id[:Display name]=redirect_uri[,redirect_uri]; separate clients with ;")
	encrypt := fs.Bool("encryption-at-rest", false, "require encrypted storage")
	firewall := fs.Bool("firewall", false, "incus: load the generated nftables rules")
	noLimits := fs.Bool("incus-no-limits", false, "incus: no memory/process limits (hosts without cgroup memory delegation)")
	verify := fs.String("require-verify", "true", "require email verification")
	fs.Parse(args)
	if *from != "" {
		base, err := os.ReadFile(*from)
		check(err)
		flagged := *c
		check(yamlInto(base, c))
		overlay(c, &flagged)
	}
	if *signin != "" {
		l := "," + *signin + ","
		c.SignIn.MagicLink, c.SignIn.Password, c.SignIn.Username = strings.Contains(l, ",magic,"), strings.Contains(l, ",password,"), strings.Contains(l, ",username,")
	}
	if *states != "" {
		c.Policy.USStates = strings.Split(strings.ToUpper(*states), ",")
	}
	for _, cl := range strings.Split(*clients, ";") {
		if id, uris, ok := strings.Cut(cl, "="); ok {
			id, name, named := strings.Cut(id, ":")
			if !named {
				name = id
			}
			c.App.Clients = append(c.App.Clients, deploy.Client{ID: id, Name: name, RedirectURIs: strings.Split(uris, ",")})
		}
	}
	c.Mail.EncryptionAtRest = c.Mail.EncryptionAtRest || *encrypt
	c.Incus.Firewall = c.Incus.Firewall || *firewall
	c.Incus.NoLimits = c.Incus.NoLimits || *noLimits
	c.SignIn.RequireVerify = *verify == "true"
	if _, err := os.Stat(*file); err == nil && !*force {
		die(*file + " exists: edit it and run `authfly deploy`, or pass --force")
	}
	c.Defaults()
	if !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			die("no terminal: run `authfly init -y` with flags for a non-interactive setup")
		}
		deploy.Wizard{In: bufio.NewReader(os.Stdin), Out: os.Stdout}.Run(c)
	}
	if len(c.App.Clients) == 0 {
		c.App.Clients = []deploy.Client{{ID: c.Name + "-app", Name: c.Name, RedirectURIs: []string{"https://" + c.Domain + "/callback"}}}
	}
	check(c.Validate())
	check(c.Save(*file))
	created, err := c.EnsureSecrets()
	check(err)
	p := deploy.PackFor(c)
	check(c.WriteDocuments(p))
	check(c.WriteAppKit())
	fmt.Printf("wrote %s (target %s, %s widgets + %s adapter, policy %s)\n", *file, c.Target, c.App.Runtime, c.App.Adapter, p.ID)
	fmt.Printf("generated %d secrets in %s (0600, values not shown)\n", len(created), c.SecretDir())
	fmt.Printf("app kit: %s/app   policy documents: %s/legal\n", c.State(), c.State())
	for _, r := range p.Reminders {
		fmt.Println("  TODO:", r)
	}
	fmt.Println("next: authfly deploy")
}

func load(path string) *deploy.Config {
	c, err := deploy.Load(path)
	check(err)
	return c
}

func check(err error) {
	if err != nil {
		die(err.Error())
	}
}

func die(m string) {
	fmt.Fprintln(os.Stderr, "authfly:", m)
	os.Exit(1)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

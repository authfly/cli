package deploy

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	Level string // PASS | WARN | FAIL | INFO
	Check string
	Note  string
}

func tcpOpen(host string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 1500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func publicIPs() []string {
	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.To4() == nil {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips
}

var ipv4Re = regexp.MustCompile(`\b(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)

// readAudit returns the Authfly audit log of the running install.
func (c *Config) readAudit() (string, error) {
	if c.Target == "incus" {
		return incus("exec", c.Name+"-authfly", "--", "cat", "/var/lib/authfly/store-audit.jsonl")
	}
	return run("docker", "compose", "-p", "authfly-"+c.Name, "-f", filepath.Join(c.State(), "compose.yml"), "exec", "-T", "authfly", "cat", "/data/store-audit.jsonl")
}

// Doctor audits a running install against authfly.yaml and its policy pack.
func (c *Config) Doctor() []Finding {
	var f []Finding
	add := func(l, ch, n string, a ...any) { f = append(f, Finding{l, ch, fmt.Sprintf(n, a...)}) }
	p := PackFor(c)
	add("PASS", "config", "%s is valid (target %s, policy %s)", filepath.Base(c.Path()), c.Target, p.ID)
	if bad := c.CheckSecretPerms(); len(bad) > 0 {
		add("FAIL", "secrets", "%s", strings.Join(bad, "; "))
	} else {
		add("PASS", "secrets", "%d secrets present, directory 0700, files 0600 (values not shown)", len(SecretNames))
	}
	if st, err := os.Stat(c.Path()); err == nil && st.Mode().Perm()&0o002 != 0 {
		add("FAIL", "config", "authfly.yaml is world-writable")
	}
	// network exposure
	scheme := "http"
	if c.HTTP.TLS != "off" {
		scheme = "https"
	}
	for _, ip := range publicIPs() {
		for name, port := range map[string]int{"Stalwart management": c.Ports.Management, "Console": c.Ports.Console, "Authfly admin API": 4001} {
			if tcpOpen(ip, port) {
				add("FAIL", "exposure", "%s port %d is reachable on %s (must be loopback only)", name, port, ip)
			}
		}
	}
	if tcpOpen("127.0.0.1", c.Ports.Management) && tcpOpen("127.0.0.1", c.Ports.Console) {
		add("PASS", "exposure", "management :%d and console :%d answer on 127.0.0.1 only (%s checked); reach them with ssh -L", c.Ports.Management, c.Ports.Console, strings.Join(publicIPs(), ", "))
	} else {
		add("FAIL", "exposure", "management or console not listening on 127.0.0.1")
	}
	if tcpOpen("127.0.0.1", 4001) {
		add("FAIL", "exposure", "Authfly admin API :4001 is published on the host")
	}
	cl := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := fmt.Sprintf("%s://127.0.0.1:%d", scheme, c.HTTP.Port)
	if c.HTTP.TLS != "off" {
		cl.Transport = &http.Transport{TLSClientConfig: &tls.Config{ServerName: hostOf(c.PublicURL)}}
	}
	get := func(u string) int {
		r, err := cl.Get(u)
		if err != nil {
			return 0
		}
		r.Body.Close()
		return r.StatusCode
	}
	if s := get(base + "/api/v1/config"); s == 200 {
		add("PASS", "authfly", "public API answers on :%d", c.HTTP.Port)
	} else {
		add("FAIL", "authfly", "public API on :%d answered %d", c.HTTP.Port, s)
	}
	if r, err := cl.Get(base + "/.well-known/openid-configuration"); err == nil {
		var d map[string]any
		json.NewDecoder(r.Body).Decode(&d)
		r.Body.Close()
		if d["issuer"] == c.PublicURL && d["registration_endpoint"] == nil {
			add("PASS", "oidc", "issuer = %s, no dynamic registration advertised", c.PublicURL)
		} else {
			add("FAIL", "oidc", "issuer %v / registration %v", d["issuer"], d["registration_endpoint"])
		}
	}
	uiOff := true
	for _, path := range []string{"/admin/", "/account/"} {
		if s := get(fmt.Sprintf("http://127.0.0.1:%d%s", c.Ports.Management, path)); s != 404 {
			add("FAIL", "stalwart", "web UI %s answers %d (must be disabled)", path, s)
			uiOff = false
		}
	}
	if uiOff {
		add("PASS", "stalwart", "web admin and self-service UI disabled (404)")
	}
	for _, path := range []string{"/jmap/session", "/api/account", "/admin"} {
		if s := get(base + path); s != 404 {
			add("FAIL", "authfly", "%s is reachable through Authfly (%d)", path, s)
		}
	}
	// sign-in methods
	if !c.SignIn.MagicLink {
		if s := get(base + "/auth/magic"); s != 404 {
			add("FAIL", "sign-in", "magic link is off in authfly.yaml but /auth/magic answers %d", s)
		}
	}
	if !c.SignIn.Password && !c.SignIn.Username {
		if s := get(base + "/auth/forgot"); s != 404 {
			add("FAIL", "sign-in", "password sign-in is off but /auth/forgot answers %d", s)
		}
	}
	add("INFO", "sign-in", "enabled: %s; social, 2FA, WebAuthn: coming", c.Methods())
	// TLS
	switch c.HTTP.TLS {
	case "off":
		add("WARN", "tls", "http.tls is off: only behind your own TLS terminator or for local tests")
	default:
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", c.HTTP.Port), &tls.Config{ServerName: hostOf(c.PublicURL)})
		if err != nil {
			add("FAIL", "tls", "TLS handshake for %s: %v", hostOf(c.PublicURL), err)
		} else {
			cert := conn.ConnectionState().PeerCertificates[0]
			conn.Close()
			if left := time.Until(cert.NotAfter); left < 14*24*time.Hour {
				add("WARN", "tls", "certificate expires in %s", left.Round(time.Hour))
			} else {
				add("PASS", "tls", "valid certificate for %s until %s", hostOf(c.PublicURL), cert.NotAfter.Format("2006-01-02"))
			}
		}
	}
	// policy pack
	if p.ID != "none" {
		for n := range p.Documents {
			if s := get(base + "/legal/" + n); s == 200 {
				add("PASS", "policy", "/legal/%s is served", n)
			} else {
				add("FAIL", "policy", "/legal/%s answered %d", n, s)
			}
		}
	}
	if audit, err := c.readAudit(); err == nil {
		if ipv4Re.MatchString(audit) {
			add("FAIL", "policy", "the audit log contains IP-like values (log IP policy: %s)", p.LogIP)
		} else {
			add("PASS", "policy", "audit log: %d records, no IP addresses (%s)", strings.Count(audit, "\n"), p.LogIP)
		}
	} else {
		add("WARN", "policy", "could not read the audit log: %v", err)
	}
	add("INFO", "policy", "audit retention %s; data-subject requests: %s; incidents: %s", fmt.Sprintf("%.0f days", p.AuditRetention.Hours()/24), p.ResponseDays, p.BreachNotice)
	if p.Residency != "" {
		switch {
		case c.Policy.HostCountry == "":
			add("FAIL", "residency", "policy requires data in %s but policy.host_country is not declared", p.Residency)
		case c.Policy.HostCountry != p.Residency:
			add("FAIL", "residency", "host_country %s, policy requires %s", c.Policy.HostCountry, p.Residency)
		default:
			add("PASS", "residency", "declared host country %s; databases are local to this host (no external stores configured)", c.Policy.HostCountry)
		}
		if strings.Contains(c.Channel.Manifest, "://") || filepath.IsAbs(c.Backup.Dir) {
			add("INFO", "residency", "backups go to %s: keep every copy in %s too", c.backupDir(), p.Residency)
		}
		add("WARN", "residency", "the physical location of this server cannot be proven by software (geo-IP is not evidence): keep the hosting contract")
	}
	for _, r := range p.Reminders {
		add("INFO", "todo", "%s", r)
	}
	// encryption at rest
	if c.Mail.EncryptionAtRest {
		if out, _ := exec.Command("lsblk", "-rno", "TYPE").Output(); strings.Contains(string(out), "crypt") {
			add("PASS", "encryption", "a dm-crypt device is present (check that the data volumes live on it)")
		} else {
			add("WARN", "encryption", "encryption_at_rest is on but no dm-crypt/LUKS device was found: put Docker/Incus storage on an encrypted disk")
		}
	}
	// releases
	st := c.LoadState()
	if m, err := c.LoadManifest(); err == nil {
		if m.SignedBy != "" {
			add("PASS", "channel", "channel.json signature verified (SSHSIG, namespace %s): %s", SigNamespace, m.SignedBy)
		} else {
			add("WARN", "channel", "unsigned channel accepted (channel.allow_unsigned, dev only): %s", c.Channel.Manifest)
		}
		if rel, err := m.Find(st.Current); err == nil {
			f = append(f, c.verifyRunning(rel)...)
		}
		if latest, _ := m.Find(""); latest != nil && latest.Version != st.Current {
			add("INFO", "update", "release %s is available (running %s): authfly upgrade", latest.Version, st.Current)
		}
	} else if errors.Is(err, ErrChannelSignature) {
		add("FAIL", "channel", "%v", err)
	} else {
		add("WARN", "update", "%v", err)
	}
	// backups
	all, _ := filepath.Glob(filepath.Join(c.backupDir(), c.Name+"-*.afbk"))
	var newest time.Time
	for _, b := range all {
		if s, err := os.Stat(b); err == nil && s.ModTime().After(newest) {
			newest = s.ModTime()
		}
	}
	if newest.IsZero() {
		add("WARN", "backup", "no backup yet: authfly backup (and copy the backup_key off this server)")
	} else if time.Since(newest) > 48*time.Hour {
		add("WARN", "backup", "newest backup is %s old", time.Since(newest).Round(time.Hour))
	} else {
		add("PASS", "backup", "newest backup %s ago, encrypted (AES-256-GCM)", time.Since(newest).Round(time.Minute))
	}
	return f
}

// verifyRunning compares what runs with the checksums in the channel.
func (c *Config) verifyRunning(rel *Release) []Finding {
	var f []Finding
	if c.Target == "incus" {
		for inst, file := range map[string][2]string{c.Name + "-authfly": {"/usr/local/bin/authfly", ArchFile("authfly")}, c.Name + "-console": {"/usr/local/bin/authfly-console", ArchFile("console")}} {
			out, err := incus("exec", inst, "--", "sha256sum", file[0])
			if a, ok := rel.Files[file[1]]; err == nil && ok && strings.HasPrefix(out, a.SHA256) {
				f = append(f, Finding{"PASS", "integrity", fmt.Sprintf("%s:%s matches channel %s", inst, file[0], rel.Version)})
			} else {
				f = append(f, Finding{"FAIL", "integrity", fmt.Sprintf("%s:%s does not match the channel checksum", inst, file[0])})
			}
		}
		return f
	}
	for svc, img := range map[string]string{"authfly": rel.Images["authfly"], "console": rel.Images["console"], "stalwart": rel.Images["stalwart"]} {
		_, digest, _ := strings.Cut(img, "@")
		id, err := run("docker", "compose", "-p", "authfly-"+c.Name, "-f", filepath.Join(c.State(), "compose.yml"), "images", "-q", svc)
		ok := false
		if err == nil {
			cid := strings.TrimSpace(id)
			out, _ := run("docker", "image", "inspect", "-f", "{{.Id}} {{range .RepoDigests}}{{.}} {{end}}", cid)
			ok = strings.Contains(out, digest)
		}
		if ok {
			f = append(f, Finding{"PASS", "integrity", fmt.Sprintf("%s image matches channel %s (%s…)", svc, rel.Version, digest[:19])})
		} else {
			f = append(f, Finding{"FAIL", "integrity", fmt.Sprintf("%s image does not match the channel digest", svc)})
		}
	}
	return f
}

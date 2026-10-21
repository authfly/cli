package deploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Incus is the bare-metal target: three unprivileged system containers (stalwart, authfly, console) on a private
// bridge, data on custom storage volumes, public ports through proxy devices, localhost-only proxy devices for the
// management ports, snapshots for upgrade rollback. Incus 6.0 LTS has no OCI support (added in 6.3), so the
// services are static binaries pushed from the host after checksum verification: the containers need no internet
// access to install anything.
type Incus struct{ C *Config }

type incusInst struct {
	role, svc, user, data string
	ipLast                int
}

func (x Incus) insts() []incusInst {
	return []incusInst{
		{"stalwart", "stalwart", "stalwart", "/var/lib/stalwart", 10},
		{"authfly", "authfly", "authfly", "/var/lib/authfly", 11},
		{"console", "authfly-console", "console", "/var/lib/authfly-console", 12},
	}
}

func (x Incus) name(role string) string { return x.C.Name + "-" + role }
func (x Incus) vol(role string) string  { return x.C.Name + "-" + role + "-data" }
func (x Incus) ip(last int) string {
	ip, _, _ := net.ParseCIDR(x.C.Incus.Subnet)
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d", v4[0], v4[1], v4[2], last)
}

func incus(args ...string) (string, error) {
	cmd := exec.Command("incus", args...)
	cmd.Stdin = nil // the incus client blocks when stdin is a pipe that never closes
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("incus %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func exists(args ...string) bool { _, err := incus(args...); return err == nil }

func (x Incus) exec(inst string, args ...string) (string, error) {
	return incus(append([]string{"exec", inst, "--"}, args...)...)
}

func (x Incus) push(inst, src, dst, mode string) error {
	_, err := incus("file", "push", "--create-dirs", "--mode", mode, src, inst+dst)
	return err
}

func (x Incus) pushData(inst, data, dst, mode string) error {
	f, err := os.CreateTemp(x.C.State(), ".push-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	os.Chmod(f.Name(), 0o600)
	f.WriteString(data)
	f.Close()
	return x.push(inst, f.Name(), dst, mode)
}

func (x Incus) infra() error {
	c := x.C
	if !exists("network", "show", c.Incus.Network) {
		Log("network %s (%s, NAT for outbound mail and ACME, no IPv6)", c.Incus.Network, c.Incus.Subnet)
		if _, err := incus("network", "create", c.Incus.Network, "ipv4.address="+c.Incus.Subnet, "ipv4.nat=true", "ipv6.address=none"); err != nil {
			return err
		}
	}
	prof := "authfly-" + c.Name
	if !exists("profile", "show", prof) {
		if _, err := incus("profile", "create", prof); err != nil {
			return err
		}
		incus("profile", "device", "add", prof, "root", "disk", "path=/", "pool="+c.Incus.Pool)
		incus("profile", "device", "add", prof, "eth0", "nic", "network="+c.Incus.Network, "name=eth0")
	}
	set := map[string]string{"boot.autostart": "true", "security.privileged": "false", "security.nesting": "false", "limits.memory": "1GiB", "limits.processes": "2000"}
	if c.Incus.NoLimits {
		delete(set, "limits.memory")
		delete(set, "limits.processes")
		incus("profile", "unset", prof, "limits.memory")
		incus("profile", "unset", prof, "limits.processes")
	}
	for k, v := range set {
		if _, err := incus("profile", "set", prof, k, v); err != nil {
			return err
		}
	}
	for _, in := range x.insts() {
		n := x.name(in.role)
		if !exists("storage", "volume", "show", c.Incus.Pool, x.vol(in.role)) {
			if _, err := incus("storage", "volume", "create", c.Incus.Pool, x.vol(in.role)); err != nil {
				return err
			}
		}
		if !exists("info", n) {
			Log("instance %s (%s, unprivileged system container)", n, c.Incus.Image)
			if _, err := incus("init", c.Incus.Image, n, "--profile", prof); err != nil {
				return err
			}
			if _, err := incus("config", "device", "override", n, "eth0", "ipv4.address="+x.ip(in.ipLast)); err != nil {
				return err
			}
			if _, err := incus("storage", "volume", "attach", c.Incus.Pool, x.vol(in.role), n, "data", in.data); err != nil {
				return err
			}
		}
		if st, _ := incus("list", n, "-c", "s", "-f", "csv"); !strings.Contains(st, "RUNNING") {
			if _, err := incus("start", n); err != nil {
				return err
			}
		}
	}
	for _, in := range x.insts() { // systemd up
		n := x.name(in.role)
		for i := 0; ; i++ {
			out, _ := x.exec(n, "systemctl", "is-system-running")
			if s := strings.TrimSpace(out); s == "running" || s == "degraded" {
				break
			}
			if i > 60 {
				return fmt.Errorf("%s: systemd did not start", n)
			}
			time.Sleep(time.Second)
		}
	}
	return nil
}

// proxy adds or updates a proxy device (idempotent).
func (x Incus) proxy(inst, dev, listen, connect string) error {
	if cur, err := incus("config", "device", "get", inst, dev, "listen"); err == nil {
		if strings.TrimSpace(cur) == listen {
			_, err := incus("config", "device", "set", inst, dev, "connect="+connect)
			return err
		}
		incus("config", "device", "remove", inst, dev)
	}
	_, err := incus("config", "device", "add", inst, dev, "proxy", "listen="+listen, "connect="+connect)
	return err
}

func unit(desc, user, exe string, args []string, env map[string]string, rw, extra string) string {
	var e strings.Builder
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&e, "Environment=%q\n", k+"="+env[k])
	}
	return fmt.Sprintf(`# GENERATED by authfly. Do not edit: change authfly.yaml and run authfly deploy.
[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
User=%s
ExecStart=%s %s
%s%sRestart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=%s
UMask=0077

[Install]
WantedBy=multi-user.target
`, desc, user, exe, strings.Join(args, " "), e.String(), extra, rw)
}

func extractStalwart(tgz, dst string) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no stalwart binary in %s", tgz)
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) == "stalwart" && h.Typeflag == tar.TypeReg {
			var b bytes.Buffer
			io.Copy(&b, tr)
			return os.WriteFile(dst, b.Bytes(), 0o755)
		}
	}
}

func (x Incus) Deploy(rel *Release, p Pack) error {
	c := x.C
	if _, err := c.EnsureSecrets(); err != nil {
		return err
	}
	creds, err := c.credentialFiles()
	if err != nil {
		return err
	}
	bins := map[string]string{}
	for _, n := range []string{"authfly-linux-amd64", "console-linux-amd64", "stalwart-linux-amd64"} {
		a, ok := rel.Files[n]
		if !ok {
			return fmt.Errorf("release %s has no %s", rel.Version, n)
		}
		path, err := c.FetchVerified(n, a)
		if err != nil {
			return err
		}
		Log("verified %s sha256 %s…", n, a.SHA256[:12])
		bins[n] = path
	}
	sw := filepath.Join(c.State(), "cache", "stalwart-"+rel.Files["stalwart-linux-amd64"].SHA256[:16])
	if err := extractStalwart(bins["stalwart-linux-amd64"], sw); err != nil {
		return err
	}
	if err := x.infra(); err != nil {
		return err
	}
	S, A, C := x.name("stalwart"), x.name("authfly"), x.name("console")
	swURL := "http://" + x.ip(10) + ":8080"
	for _, in := range x.insts() {
		n := x.name(in.role)
		x.exec(n, "sh", "-c", "id "+in.user+" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "+in.user)
		x.exec(n, "sh", "-c", "chown "+in.user+": "+in.data+" && chmod 0700 "+in.data)
	}
	// Stalwart
	if err := x.push(S, sw, "/usr/local/bin/stalwart", "0755"); err != nil {
		return err
	}
	x.pushData(S, `{"@type":"RocksDb","path":"/var/lib/stalwart/"}`+"\n", "/etc/stalwart/config.json", "0644")
	x.pushData(S, creds["stalwart.env"], "/etc/stalwart/env", "0600")
	x.pushData(S, unit("Stalwart mail server (Authfly)", "stalwart", "/usr/local/bin/stalwart", []string{"--config", "/etc/stalwart/config.json"},
		map[string]string{"STALWART_PUBLIC_URL": c.PublicURL}, "/var/lib/stalwart", "EnvironmentFile=/etc/stalwart/env\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nLimitNOFILE=65536\n"),
		"/etc/systemd/system/stalwart.service", "0644")
	// Authfly + Console binaries and secrets
	const sd = "/etc/authfly/secrets"
	for inst, files := range map[string][]string{A: {"stalwart_service", "authfly_secret", "admin_key", "stalwart_admin", "service_password"}, C: {"stalwart_admin", "admin_key", "console_admin", "console_secret"}} {
		user := "authfly"
		if inst == C {
			user = "console"
		}
		for _, f := range files {
			if err := x.pushData(inst, creds[f], sd+"/"+f, "0600"); err != nil {
				return err
			}
		}
		x.exec(inst, "sh", "-c", "chown -R "+user+": /etc/authfly && chmod 0700 "+sd)
	}
	if err := x.push(A, bins["authfly-linux-amd64"], "/usr/local/bin/authfly", "0755"); err != nil {
		return err
	}
	if err := x.push(C, bins["console-linux-amd64"], "/usr/local/bin/authfly-console", "0755"); err != nil {
		return err
	}
	for n, d := range p.Documents {
		x.pushData(A, d, "/etc/authfly/legal/"+n+".md", "0644")
	}
	ae := c.authflyEnv(p, swURL, x.ip(10)+":25", sd, "/var/lib/authfly")
	ae["AUTHFLY_LEGAL_DIR"] = "/etc/authfly/legal"
	bind := ""
	if c.HTTP.TLS != "off" { // 4443/4080 inside; unprivileged
		bind = ""
	}
	x.pushData(A, unit("Authfly", "authfly", "/usr/local/bin/authfly", nil, ae, "/var/lib/authfly", bind), "/etc/systemd/system/authfly.service", "0644")
	x.pushData(C, unit("Authfly Console", "console", "/usr/local/bin/authfly-console", nil, c.consoleEnv(swURL, "http://"+x.ip(11)+":4001", sd, "/var/lib/authfly-console"), "/var/lib/authfly-console", ""),
		"/etc/systemd/system/authfly-console.service", "0644")
	// start Stalwart, harden it, then Authfly and the Console
	x.exec(S, "systemctl", "daemon-reload")
	if _, err := x.exec(S, "systemctl", "enable", "--now", "stalwart"); err != nil {
		return err
	}
	x.exec(S, "systemctl", "restart", "stalwart")
	Log("init-stalwart (least-privilege service account, web admin off, OIDC clients)")
	args := []string{"exec", A}
	for k, v := range c.initEnv(swURL, sd) {
		args = append(args, "--env", k+"="+v)
	}
	if out, err := incus(append(args, "--", "/usr/local/bin/authfly", "init-stalwart")...); err != nil {
		return fmt.Errorf("init-stalwart: %w\n%s", err, out)
	}
	for _, in := range []string{A, C} {
		svc := map[string]string{A: "authfly", C: "authfly-console"}[in]
		x.exec(in, "systemctl", "daemon-reload")
		if _, err := x.exec(in, "systemctl", "enable", svc); err != nil {
			return err
		}
		if _, err := x.exec(in, "systemctl", "restart", svc); err != nil {
			return err
		}
	}
	// ports: public through proxy devices, management on the host's loopback only
	pub := "0.0.0.0"
	x.proxy(S, "smtp", fmt.Sprintf("tcp:%s:%d", pub, c.Mail.Ports.SMTP), "tcp:127.0.0.1:25")
	x.proxy(S, "submissions", fmt.Sprintf("tcp:%s:%d", pub, c.Mail.Ports.Submissions), "tcp:127.0.0.1:465")
	x.proxy(S, "imaps", fmt.Sprintf("tcp:%s:%d", pub, c.Mail.Ports.IMAPS), "tcp:127.0.0.1:993")
	x.proxy(S, "management", fmt.Sprintf("tcp:127.0.0.1:%d", c.Ports.Management), "tcp:127.0.0.1:8080")
	if c.HTTP.TLS == "off" {
		x.proxy(A, "http", fmt.Sprintf("tcp:%s:%d", pub, c.HTTP.Port), "tcp:127.0.0.1:4000")
	} else {
		x.proxy(A, "https", fmt.Sprintf("tcp:%s:%d", pub, c.HTTP.Port), "tcp:127.0.0.1:4443")
		if c.HTTP.HTTPPort != 0 {
			x.proxy(A, "http", fmt.Sprintf("tcp:%s:%d", pub, c.HTTP.HTTPPort), "tcp:127.0.0.1:4080")
		}
	}
	x.proxy(C, "console", fmt.Sprintf("tcp:127.0.0.1:%d", c.Ports.Console), "tcp:127.0.0.1:4500")
	if err := x.firewall(); err != nil {
		return err
	}
	scheme := "http"
	if c.HTTP.TLS != "off" {
		scheme = "https"
	}
	return waitHTTP(fmt.Sprintf("%s://127.0.0.1:%d/api/v1/config", scheme, c.HTTP.Port), 90*time.Second)
}

func (x Incus) Status() (string, error) {
	out, err := incus("list", x.C.Name+"-", "-c", "ns4tS", "-f", "table")
	if err != nil {
		return out, err
	}
	for _, in := range x.insts() {
		st, _ := x.exec(x.name(in.role), "systemctl", "is-active", in.svc)
		out += fmt.Sprintf("%s: service %s %s\n", x.name(in.role), in.svc, strings.TrimSpace(st))
	}
	return out, nil
}

func (x Incus) Parts() []string { return []string{"stalwart", "authfly", "console"} }
func (x Incus) inst(part string) incusInst {
	for _, in := range x.insts() {
		if in.role == part {
			return in
		}
	}
	return incusInst{}
}

func (x Incus) Stop() error {
	for _, in := range []string{"console", "authfly", "stalwart"} {
		if _, err := x.exec(x.name(in), "systemctl", "stop", x.inst(in).svc); err != nil {
			return err
		}
	}
	return nil
}

func (x Incus) Start() error {
	for _, in := range []string{"stalwart", "authfly", "console"} {
		if _, err := x.exec(x.name(in), "systemctl", "start", x.inst(in).svc); err != nil {
			return err
		}
	}
	return nil
}

func (x Incus) Dump(part string) ([]byte, error) {
	cmd := exec.Command("incus", "exec", x.name(part), "--", "tar", "-C", x.inst(part).data, "-cf", "-", ".")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, errb.String())
	}
	return out.Bytes(), nil
}

func (x Incus) Load(part string, data []byte) error {
	in := x.inst(part)
	cmd := exec.Command("incus", "exec", x.name(part), "--", "sh", "-c", "find "+in.data+" -mindepth 1 -delete && tar -C "+in.data+" -xpf - && chown -R "+in.user+": "+in.data)
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Snapshot: instance snapshots (binaries, units, secrets) + custom volume snapshots (data), taken with services stopped.
func (x Incus) Snapshot(tag string) error {
	if err := x.Stop(); err != nil {
		return err
	}
	defer x.Start()
	for _, in := range x.insts() {
		if _, err := incus("snapshot", "create", x.name(in.role), tag); err != nil {
			return err
		}
		if _, err := incus("storage", "volume", "snapshot", "create", x.C.Incus.Pool, x.vol(in.role), tag); err != nil {
			return err
		}
	}
	return nil
}

func (x Incus) RestoreSnapshot(tag string) error {
	for _, in := range x.insts() {
		n := x.name(in.role)
		if _, err := incus("stop", n, "--timeout", "30"); err != nil {
			incus("stop", n, "--force")
		}
		if _, err := incus("snapshot", "restore", n, tag); err != nil {
			return err
		}
		if _, err := incus("storage", "volume", "snapshot", "restore", x.C.Incus.Pool, x.vol(in.role), tag); err != nil {
			return err
		}
	}
	for _, in := range x.insts() {
		if _, err := incus("start", x.name(in.role)); err != nil {
			return err
		}
	}
	return waitHTTP(fmt.Sprintf("http://127.0.0.1:%d/api/v1/config", x.C.HTTP.Port), 90*time.Second)
}

// Down deletes the instances (and with purge the volumes, profile and network).
func (x Incus) Down(purge bool) error {
	for _, in := range x.insts() {
		incus("delete", "--force", x.name(in.role))
		if purge {
			incus("storage", "volume", "delete", x.C.Incus.Pool, x.vol(in.role))
		}
	}
	if purge {
		incus("profile", "delete", "authfly-"+x.C.Name)
		incus("network", "delete", x.C.Incus.Network)
	}
	return nil
}

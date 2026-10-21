package deploy

import (
	"fmt"
	"time"
)

// Deploy is idempotent: secrets are created once, the generated files are rewritten from authfly.yaml, and the
// driver converges the running install to them.
func (c *Config) Deploy() error {
	m, err := c.LoadManifest()
	if err != nil {
		return err
	}
	st := c.LoadState()
	v := st.Current // re-deploys keep the running release; `authfly upgrade` moves forward
	if v == "" {
		v = c.Channel.Version // first deploy: the pinned release, or the newest when empty
	}
	rel, err := m.Find(v)
	if err != nil {
		return err
	}
	p := PackFor(c)
	if created, err := c.EnsureSecrets(); err != nil {
		return err
	} else if len(created) > 0 {
		Log("generated %d secrets in %s (0600, not shown)", len(created), c.SecretDir())
	}
	if err := c.WriteDocuments(p); err != nil {
		return err
	}
	if err := c.WriteAppKit(); err != nil {
		return err
	}
	Log("deploying release %s to %s (policy %s)", rel.Version, c.Target, p.ID)
	if err := c.Driver().Deploy(rel, p); err != nil {
		return err
	}
	if st.Current != rel.Version {
		st.Previous, st.Current = st.Current, rel.Version
	}
	return c.SaveState(st)
}

// Upgrade: snapshot (rollback point), deploy the target release, health check; on failure roll back automatically.
func (c *Config) Upgrade(to string) error {
	m, err := c.LoadManifest()
	if err != nil {
		return err
	}
	st := c.LoadState()
	rel, err := m.Find(to)
	if err != nil {
		return err
	}
	if rel.Version == st.Current {
		Log("already on %s", rel.Version)
		return nil
	}
	tag := "pre-" + rel.Version + "-" + time.Now().UTC().Format("20060102T150405")
	Log("snapshot %s (rollback point for %s)", tag, st.Current)
	d := c.Driver()
	if err := d.Snapshot(tag); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	from := st.Current
	st.Snapshot, st.Previous, st.Current = tag, from, rel.Version // recorded before the switch so a failed upgrade can roll back
	c.SaveState(st)
	Log("upgrading %s -> %s", from, rel.Version)
	if err := d.Deploy(rel, PackFor(c)); err != nil {
		Log("upgrade failed (%v): rolling back", err)
		if rerr := c.Rollback(); rerr != nil {
			return fmt.Errorf("upgrade failed: %v; rollback failed too: %w", err, rerr)
		}
		return fmt.Errorf("upgrade failed and was rolled back: %w", err)
	}
	return c.SaveState(st)
}

// Rollback restores the pre-upgrade snapshot (data + previous release).
func (c *Config) Rollback() error {
	st := c.LoadState()
	if st.Snapshot == "" || st.Previous == "" {
		return fmt.Errorf("nothing to roll back to (no upgrade snapshot recorded)")
	}
	m, err := c.LoadManifest()
	if err != nil {
		return err
	}
	prev, err := m.Find(st.Previous)
	if err != nil {
		return err
	}
	Log("rolling back to %s from snapshot %s", prev.Version, st.Snapshot)
	d := c.Driver()
	if c.Target == "docker" {
		if err := d.Deploy(prev, PackFor(c)); err != nil { // previous images first, then the data
			return err
		}
	}
	if err := d.RestoreSnapshot(st.Snapshot); err != nil {
		return err
	}
	st.Current, st.Previous, st.Snapshot = prev.Version, st.Current, ""
	return c.SaveState(st)
}

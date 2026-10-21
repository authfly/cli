package core

// Hardening of a Stalwart server for Authfly, run once with the bootstrap admin (`authfly init-stalwart`). Every step
// is idempotent and was verified live against v0.16.27:
//   - the mail domain (x:Domain)
//   - a least-privilege role "authfly-service" (x:Role): inherits the built-in User role (Stalwart refuses to let an
//     account grant permissions it does not hold, so creating user accounts needs the User permissions) plus only the
//     account management, domain read and mailbox read-for-export permissions; no settings, queue, roles, logs or
//     other sys* objects
//   - the service account Authfly authenticates with (x:Account, custom role)
//   - the bundled web admin and self-service UI off (x:Application enabled=false; /admin and /account answer 404)
//   - OIDC: no anonymous dynamic client registration, client ids must be registered (x:OidcProvider), and the
//     relying parties registered as x:OAuthClient with their redirect URIs
//   - no redirect of / to the web UI (x:Http redirectRoot null)
//   - then x:Action UpdateApps + ReloadSettings so it applies without a restart

import (
	"context"
	"encoding/json"
	"fmt"
)

// ServicePermissions are the permissions the Authfly service role adds on top of the User role.
var ServicePermissions = []string{
	"sysAccountGet", "sysAccountQuery", "sysAccountCreate", "sysAccountUpdate", "sysAccountDestroy",
	"sysDomainGet", "sysDomainQuery",
	// GDPR export: read another account's mailbox through JMAP (accountId of the user)
	"impersonate", "fetchAnyBlob",
	// GDPR erasure: purge the blob store right away instead of at the daily blobCleanupSchedule (StoreMaintenance/purgeBlob)
	"sysTaskCreate", "taskStoreMaintenance",
}

const ServiceRoleName = "authfly-service"

type HardenOptions struct {
	Domain          string
	ServiceName     string // local part of the service account, e.g. authfly-svc
	ServicePassword string
	KeepWebUI       bool
	Clients         []OAuthClient
}

type OAuthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
}

func setOK(r [][]json.RawMessage, kind string) error {
	for _, m := range r {
		var res map[string]json.RawMessage
		_ = json.Unmarshal(m[1], &res)
		for _, k := range []string{"notCreated", "notUpdated", "notDestroyed"} {
			if v, ok := res[k]; ok && string(v) != "null" && string(v) != "{}" {
				return fmt.Errorf("%s: %s %s", kind, k, v)
			}
		}
	}
	return nil
}

// queryGet runs x:<obj>/query + /get and returns the list.
func (s *Stalwart) queryGet(ctx context.Context, obj string, props []string) ([]map[string]any, error) {
	get := map[string]any{"#ids": map[string]any{"resultOf": "q", "name": obj + "/query", "path": "/ids"}}
	if props != nil {
		get["properties"] = props
	}
	r, err := s.JMAP(ctx, []any{obj + "/query", map[string]any{}, "q"}, []any{obj + "/get", get, "g"})
	if err != nil {
		return nil, err
	}
	var out struct {
		List []map[string]any `json:"list"`
	}
	_ = json.Unmarshal(r[1][1], &out)
	return out.List, nil
}

// Harden applies the steps; it returns a log line per step.
func (s *Stalwart) Harden(ctx context.Context, o HardenOptions) ([]string, error) {
	var log []string
	domainID, err := s.EnsureDomain(ctx, o.Domain)
	if err != nil {
		return log, fmt.Errorf("domain: %w", err)
	}
	log = append(log, "domain "+o.Domain+" id "+domainID)

	// the built-in User role (description "User") and the service role
	roles, err := s.queryGet(ctx, "x:Role", []string{"description"})
	if err != nil {
		return log, err
	}
	userRole, svcRole := "", ""
	for _, r := range roles {
		switch r["description"] {
		case "User":
			userRole, _ = r["id"].(string)
		case ServiceRoleName:
			svcRole, _ = r["id"].(string)
		}
	}
	if userRole == "" {
		return log, fmt.Errorf("built-in User role not found")
	}
	perms := map[string]bool{"authenticate": true}
	for _, p := range ServicePermissions {
		perms[p] = true
	}
	role := map[string]any{"description": ServiceRoleName, "roleIds": map[string]bool{userRole: true}, "enabledPermissions": perms}
	if svcRole == "" {
		r, err := s.JMAP(ctx, []any{"x:Role/set", map[string]any{"create": map[string]any{"r": role}}, "c"})
		if err != nil {
			return log, err
		}
		if err := setOK(r, "role"); err != nil {
			return log, err
		}
		var c struct {
			Created map[string]struct{ ID string } `json:"created"`
		}
		_ = json.Unmarshal(r[0][1], &c)
		svcRole = c.Created["r"].ID
		log = append(log, "role "+ServiceRoleName+" created id "+svcRole)
	} else {
		r, err := s.JMAP(ctx, []any{"x:Role/set", map[string]any{"update": map[string]any{svcRole: role}}, "u"})
		if err == nil {
			err = setOK(r, "role")
		}
		if err != nil {
			return log, err
		}
		log = append(log, "role "+ServiceRoleName+" updated id "+svcRole)
	}

	// service account
	acc, err := s.FindAccount(ctx, o.Domain, o.ServiceName)
	if err != nil && err != ErrNotFound {
		return log, err
	}
	fields := map[string]any{"roles": map[string]any{"@type": "Custom", "roleIds": map[string]bool{svcRole: true}}, "permissions": map[string]any{"@type": "Inherit"},
		"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": o.ServicePassword}}, "description": "Authfly service account"}
	if acc == nil {
		fields["@type"], fields["name"], fields["domainId"], fields["encryptionAtRest"] = "User", o.ServiceName, domainID, map[string]any{"@type": "Disabled"}
		r, err := s.JMAP(ctx, []any{"x:Account/set", map[string]any{"create": map[string]any{"s": fields}}, "c"})
		if err == nil {
			err = setOK(r, "service account")
		}
		if err != nil {
			return log, err
		}
		log = append(log, "service account "+o.ServiceName+"@"+o.Domain+" created")
	} else {
		r, err := s.JMAP(ctx, []any{"x:Account/set", map[string]any{"update": map[string]any{acc.ID: fields}}, "u"})
		if err == nil {
			err = setOK(r, "service account")
		}
		if err != nil {
			return log, err
		}
		log = append(log, "service account "+o.ServiceName+"@"+o.Domain+" updated")
	}

	// web UI
	if !o.KeepWebUI {
		apps, err := s.queryGet(ctx, "x:Application", []string{"description", "enabled"})
		if err != nil {
			return log, err
		}
		for _, a := range apps {
			id, _ := a["id"].(string)
			r, err := s.JMAP(ctx, []any{"x:Application/set", map[string]any{"update": map[string]any{id: map[string]any{"enabled": false}}}, "u"})
			if err == nil {
				err = setOK(r, "application")
			}
			if err != nil {
				return log, err
			}
			log = append(log, fmt.Sprintf("web application %q disabled", a["description"]))
		}
	}
	r, err := s.JMAP(ctx, []any{"x:Http/set", map[string]any{"update": map[string]any{"singleton": map[string]any{"redirectRoot": nil}}}, "h"},
		[]any{"x:OidcProvider/set", map[string]any{"update": map[string]any{"singleton": map[string]any{"anonymousClientRegistration": false, "requireClientRegistration": true}}}, "o"})
	if err == nil {
		err = setOK(r, "http/oidc")
	}
	if err != nil {
		return log, err
	}
	log = append(log, "http redirectRoot off; oidc: anonymous registration off, registered clients required")
	// apply without a restart: UpdateApps reloads the web applications (a disabled one stops being served, verified
	// live: /admin/ 200 -> 404), ReloadSettings the settings
	r, err = s.JMAP(ctx, []any{"x:Action/set", map[string]any{"create": map[string]any{"a": map[string]any{"@type": "UpdateApps"}, "s": map[string]any{"@type": "ReloadSettings"}}}, "a"})
	if err == nil {
		err = setOK(r, "actions")
	}
	if err != nil {
		return log, err
	}
	log = append(log, "actions UpdateApps, ReloadSettings")

	// OAuth clients
	have, err := s.queryGet(ctx, "x:OAuthClient", []string{"clientId"})
	if err != nil {
		return log, err
	}
	ids := map[string]string{}
	for _, c := range have {
		cid, _ := c["clientId"].(string)
		ids[cid], _ = c["id"].(string)
	}
	for _, c := range o.Clients {
		uris := map[string]bool{}
		for _, u := range c.RedirectURIs {
			uris[u] = true
		}
		obj := map[string]any{"clientId": c.ID, "description": c.Name, "redirectUris": uris}
		var call []any
		if id, ok := ids[c.ID]; ok {
			call = []any{"x:OAuthClient/set", map[string]any{"update": map[string]any{id: obj}}, "u"}
		} else {
			call = []any{"x:OAuthClient/set", map[string]any{"create": map[string]any{"c": obj}}, "c"}
		}
		r, err := s.JMAP(ctx, call)
		if err == nil {
			err = setOK(r, "oauth client "+c.ID)
		}
		if err != nil {
			return log, err
		}
		log = append(log, "oauth client "+c.ID+" registered")
	}
	return log, nil
}

package main

// Curated knowledge the schema does not carry: side effects of changes, settings that depend on each other, and which
// operations are destructive or touch personal data. Everything here was checked against Stalwart v0.16.27
// (docs/stalwart-api.md, docs/api-capture/notes.md).

type Note struct {
	Effects []string // what happens when you change it
	Depends []string // settings it depends on / that depend on it
	GDPR    string   // personal-data relevance
	Danger  string   // why deleting is dangerous
}

var notes = map[string]Note{
	"x:Account": {
		Effects: []string{"Creating a user creates its mailbox immediately; it can receive mail at name@domain.",
			"Changing name or domainId changes the email address; mail to the old address bounces unless you add an alias.",
			"Setting credentials replaces the password; existing Stalwart OAuth tokens stay valid until they expire. Authkit sessions are revoked by its password-reset flow, not by this edit."},
		Depends: []string{"domainId must reference an existing x:Domain.", "roles: an account can only be given permissions the caller holds (escalation is refused).",
			"The Authkit service account uses the custom role authkit-service; do not edit it here, run init-stalwart."},
		GDPR:   "An account is personal data (name, address, mailbox). Use the GDPR actions on the user page for export and erasure, so Authkit's sessions, consent records and audit log follow.",
		Danger: "Destroying an account deletes its mailbox, contacts, calendars and files. x:DataRetention.archiveDeletedAccountsFor decides whether Enterprise keeps an archive (null in this deployment: nothing is kept).",
	},
	"x:Domain": {
		Effects: []string{"A new domain makes Stalwart accept mail for it; publish MX, SPF, DKIM and DMARC records (DNS view) before use.",
			"Disabling or deleting the Authkit domain breaks sign-up and sign-in for every user."},
		Depends: []string{"x:Account.domainId references it", "x:DkimSignature keys are per domain", "AUTHKIT_DOMAIN must match the domain name"},
		Danger:  "Deleting a domain that still has accounts is refused or orphans them; move or erase the accounts first.",
	},
	"x:OAuthClient": {
		Effects: []string{"Registering a client lets it start the authorization-code flow with these redirect URIs.",
			"Removing a redirect URI breaks the client's sign-in immediately."},
		Depends: []string{"x:OidcProvider.requireClientRegistration=true makes this list the allowlist (set by init-stalwart).",
			"The Authkit core needs a client with redirect AUTHKIT_PUBLIC_URL/auth/callback (id AUTHKIT_CLIENT_ID)."},
		Danger: "Deleting the authkit client stops every hosted sign-in.",
	},
	"x:OidcProvider": {
		Effects: []string{"anonymousClientRegistration=true would let anyone register clients through /auth/register (Authkit blocks the path, but keep it false).",
			"requireClientRegistration=false would accept any client id."},
		Depends: []string{"Issuer comes from STALWART_PUBLIC_URL (= Authkit's public URL); Authkit proxies only the OIDC endpoints."},
	},
	"x:Application": {
		Effects: []string{"Enabling the web admin or account app publishes /admin or /account on Stalwart's HTTP listener (localhost-only here)."},
		Depends: []string{"Takes effect only after the UpdateApps action (x:Action) or a restart; ReloadSettings alone is not enough."},
	},
	"x:Role": {
		Effects: []string{"Changing a role changes the permissions of every account holding it at once."},
		Depends: []string{"The authkit-service role must keep sysAccount*, sysDomainGet/Query, impersonate and fetchAnyBlob, and inherit User; the security test checks the rest stays denied."},
		Danger:  "Deleting a role in use removes those permissions from its accounts.",
	},
	"x:DataRetention": {
		Effects: []string{"Controls how long Stalwart keeps deleted items, traces, metrics and archived accounts."},
		GDPR:    "archiveDeletedAccountsFor must stay null for erasure to remove the data at once; expungeTrashAfter limits how long deleted mail stays recoverable.",
	},
	"x:Email": {
		Effects: []string{"encryptAtRest allows users to encrypt stored mail with their own OpenPGP or S/MIME key (x:Account.encryptionAtRest)."},
		GDPR:    "Encryption at rest per account protects stored mail (Art. 32).",
	},
	"x:Http": {
		Effects: []string{"Changing listeners, rate limits or headers affects every HTTP client, including Authkit's OIDC proxy."},
		Depends: []string{"The compose file binds HTTP to 127.0.0.1:8080; Authkit reaches it as stalwart:8080 on the internal network."},
	},
	"x:QueuedMessage": {
		Effects: []string{"Destroying a queued message drops it without a bounce."},
		GDPR:    "Queued messages contain personal data in transit.",
		Danger:  "The message is lost; the sender is not notified.",
	},
	"x:MailingList": {Depends: []string{"Members are addresses or accounts; the list address must be on a local domain."}},
	"x:DkimSignature": {Depends: []string{"Per domain; publish the DNS record before enabling, or receivers will reject signed mail."},
		Danger: "Deleting the active key makes signed mail fail DKIM until DNS is updated."},
	"x:Action": {Effects: []string{"Runs a server task now: ReloadSettings, UpdateApps, ReloadTlsCertificates, ... The effect is immediate and cannot be undone."}},
}

func noteFor(v *View) Note { return notes[v.Object] }

// Method explanations for the request builder.
var methodHelp = map[string]string{
	"get":     "Read objects by id (singletons: id \"singleton\"). No side effects.",
	"query":   "List ids, optionally filtered and sorted. No side effects.",
	"changes": "Ids created, updated or destroyed since a state string. No side effects.",
	"set":     "Create, update (patch) or destroy objects. Changes the server immediately; destroy cannot be undone.",
}

// restricted explains objects that cannot be listed by the console's admin (checked live, docs/stalwart-api.md).
var restricted = map[string]string{
	"x:ArchivedItem":    "Enterprise edition only: the community edition answers with an error.",
	"x:Trace":           "Enterprise edition only (tracing store).",
	"x:Metric":          "Enterprise edition only (metrics store).",
	"x:MaskedEmail":     "Enterprise edition only.",
	"x:ApiKey":          "Per-account object: it belongs to the account that is signed in, so a user manages it in their own account, not here.",
	"x:AppPassword":     "Per-account object: it belongs to the account that is signed in, so a user manages it in their own account, not here.",
	"x:AccountPassword": "Per-account object of the signed-in account; change a user's password on the Users page instead.",
	"x:AccountSettings": "Per-account object of the signed-in account.",
	"x:Action":          "Set-only: create an Action to run a task (ReloadSettings, UpdateApps, ...). There is nothing to list.",
	"x:Log":             "Needs a log store; none is configured in this deployment (serverUnavailable). Use `docker compose logs stalwart`.",
	"x:Bootstrap":       "Only exists during the first-run setup, which this deployment skips with a declarative config.",
}

func restrictedBlock(v *View, err error) Block {
	if why, ok := restricted[v.Object]; ok {
		return Block{Kind: "alert", Icon: "info", Title: "Not listable here", Text: why}
	}
	return errBlock("Could not read "+v.Label, err)
}

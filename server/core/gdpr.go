package core

// GDPR operations of the core: export (Art. 15 access, Art. 20 portability) and erasure (Art. 17). docs/gdpr.md has
// the design and what was verified live against Stalwart v0.16.27.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

var mailUsing = []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission", "urn:stalwart:jmap"}

// ExportLimit caps the messages per export file (bodies included); the export says when it was truncated.
var ExportLimit = 5000

// Export collects everything about an account: the directory record (without credentials), what Authfly holds
// (verification, consent records, revocations), the audit trail, and the mailbox (mailboxes, identities, messages
// with headers and text bodies) read over JMAP with the service account's impersonate permission.
func (s *Service) Export(ctx context.Context, addr, actor string) (map[string]any, error) {
	local, err := s.LocalPart(addr)
	if err != nil {
		return nil, err
	}
	addr = s.address(local)
	acc, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"format": "authfly-export/1", "exportedAt": time.Now().UTC().Format(time.RFC3339), "subject": addr}
	r, err := s.SW.JMAP(ctx, []any{"x:Account/get", map[string]any{"ids": []string{acc.ID}}, "a"})
	if err != nil {
		return nil, err
	}
	var ag struct {
		List []map[string]any `json:"list"`
	}
	_ = json.Unmarshal(r[0][1], &ag)
	if len(ag.List) > 0 {
		rec := ag.List[0]
		delete(rec, "credentials") // hashes are not personal data the user can use, and must not leave the server
		out["account"] = rec
	}
	out["authfly"] = s.Store.Snapshot(addr)
	out["audit"] = s.Audit.Query(addr, 0)
	mr, err := s.SW.JMAPUsing(ctx, mailUsing,
		[]any{"Mailbox/get", map[string]any{"accountId": acc.ID, "ids": nil}, "m"},
		[]any{"Identity/get", map[string]any{"accountId": acc.ID, "ids": nil}, "i"},
		[]any{"Email/query", map[string]any{"accountId": acc.ID, "limit": ExportLimit, "sort": []map[string]any{{"property": "receivedAt", "isAscending": true}}, "calculateTotal": true}, "q"},
		[]any{"Email/get", map[string]any{"accountId": acc.ID, "#ids": map[string]any{"resultOf": "q", "name": "Email/query", "path": "/ids"},
			"properties":          []string{"id", "mailboxIds", "keywords", "receivedAt", "sentAt", "from", "to", "cc", "bcc", "replyTo", "subject", "messageId", "size", "textBody", "bodyValues", "attachments"},
			"fetchTextBodyValues": true, "maxBodyValueBytes": 1 << 20}, "e"})
	if err != nil {
		return nil, fmt.Errorf("mailbox export: %w", err)
	}
	pick := func(i int, key string) any {
		var m map[string]any
		_ = json.Unmarshal(mr[i][1], &m)
		return m[key]
	}
	var q struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(mr[2][1], &q)
	emails, _ := pick(3, "list").([]any)
	out["mailbox"] = map[string]any{"mailboxes": pick(0, "list"), "identities": pick(1, "list"), "emails": emails, "total": q.Total, "truncated": q.Total > len(emails),
		"note": "attachments are listed with their blobId; download them with JMAP blob download as the account"}
	s.Audit.Log(actor, addr, "export", "ok", map[string]string{"emails": fmt.Sprint(len(emails))})
	return out, nil
}

// ErasureReport says what was removed.
type ErasureReport struct {
	Subject            string   `json:"subject"`
	Pseudonym          string   `json:"pseudonym"`
	StalwartAccount    string   `json:"stalwartAccount"` // destroyed id
	MessagesBefore     int      `json:"messagesBefore"`
	AuditPseudonymised int      `json:"auditPseudonymised"`
	Steps              []string `json:"steps"`
	Verified           bool     `json:"verified"`  // sampled messages are no longer readable
	BlobPurge          string   `json:"blobPurge"` // scheduled | deferred
}

// Erase removes an account: the Stalwart account with its mailbox (x:Account/set destroy), every Authfly session
// (revocation), what Authfly stores (verification, consent records), and replaces the address in the audit log with a
// pseudonym. The erasure itself is logged under the pseudonym.
func (s *Service) Erase(ctx context.Context, addr, actor string) (*ErasureReport, error) {
	local, err := s.LocalPart(addr)
	if err != nil {
		return nil, err
	}
	addr = s.address(local)
	acc, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local)
	if err != nil {
		return nil, err
	}
	rep := &ErasureReport{Subject: addr, Pseudonym: Pseudonym(addr), StalwartAccount: acc.ID}
	var sample []string
	if mr, err := s.SW.JMAPUsing(ctx, mailUsing, []any{"Email/query", map[string]any{"accountId": acc.ID, "calculateTotal": true, "limit": 50}, "q"}); err == nil {
		var q struct {
			Total int      `json:"total"`
			IDs   []string `json:"ids"`
		}
		_ = json.Unmarshal(mr[0][1], &q)
		rep.MessagesBefore, sample = q.Total, q.IDs
	}
	r, err := s.SW.JMAP(ctx, []any{"x:Account/set", map[string]any{"destroy": []string{acc.ID}}, "d"})
	if err != nil {
		return nil, err
	}
	if err := setOK(r, "destroy account"); err != nil {
		return nil, err
	}
	rep.Steps = append(rep.Steps, "stalwart account "+acc.ID+" destroyed with its mailbox (x:Account/set destroy schedules DestroyAccount, which runs at once in the community edition)")
	// verify: the messages are no longer readable (Email/get by id returns notFound)
	if len(sample) > 0 {
		time.Sleep(500 * time.Millisecond)
		left := len(sample)
		for i := 0; i < 10 && left > 0; i++ {
			if mr, err := s.SW.JMAPUsing(ctx, mailUsing, []any{"Email/get", map[string]any{"accountId": acc.ID, "ids": sample, "properties": []string{"id"}}, "g"}); err == nil {
				var g struct {
					List []any `json:"list"`
				}
				_ = json.Unmarshal(mr[0][1], &g)
				left = len(g.List)
			}
			if left > 0 {
				time.Sleep(time.Second)
			}
		}
		rep.Verified = left == 0
		rep.Steps = append(rep.Steps, fmt.Sprintf("verified: %d of %d sampled messages still readable", left, len(sample)))
	} else {
		rep.Verified = true
	}
	// purge the blob store now (best effort; otherwise blobCleanupSchedule does it, daily by default)
	if r, err := s.SW.JMAP(ctx, []any{"x:Task/set", map[string]any{"create": map[string]any{"p": map[string]any{"@type": "StoreMaintenance", "maintenanceType": "purgeBlob"}}}, "p"}); err == nil && setOK(r, "purge task") == nil {
		rep.Steps = append(rep.Steps, "blob store purge scheduled (StoreMaintenance purgeBlob)")
		rep.BlobPurge = "scheduled"
	} else {
		rep.Steps = append(rep.Steps, "blob store purge not scheduled (missing sysTaskCreate/taskStoreMaintenance?): blobs go at the next blobCleanupSchedule run")
		rep.BlobPurge = "deferred"
	}
	s.Store.Forget(addr)
	rep.Steps = append(rep.Steps, "authfly sessions revoked, verification and consent records deleted")
	rep.AuditPseudonymised = s.Audit.Pseudonymise(addr)
	rep.Steps = append(rep.Steps, fmt.Sprintf("audit log: %d entries pseudonymised to %s", rep.AuditPseudonymised, rep.Pseudonym))
	s.Audit.Log(actor, rep.Pseudonym, "erase", "ok", map[string]string{"messages": fmt.Sprint(rep.MessagesBefore)})
	return rep, nil
}

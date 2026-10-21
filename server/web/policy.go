package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/authfly/cli/server/core"
)

// Policy is set from authfly.yaml (the policy pack) through the environment: AUTHFLY_POLICY, AUTHFLY_LEGAL_DIR,
// AUTHFLY_TERMS_LABEL, AUTHFLY_EXTRA_CONSENTS.
var Policy struct {
	Pack          string   // gdpr | us-pii | ru-152fz | ""
	LegalDir      string   // generated documents served at /legal/{name} (privacy, pd-consent, ...)
	TermsLabel    string   // sign-up checkbox text (links to the separate consent document under 152-FZ)
	ExtraConsents []string // consent kinds recorded with the sign-up checkbox, e.g. pd_processing (152-FZ Art. 9)
}

// policyConsents records the pack's extra consent kinds (each its own record, with the document version).
func (s *Server) policyConsents(addr, version string) {
	for _, k := range Policy.ExtraConsents {
		s.Svc.Store.AddConsent(addr, core.Consent{Kind: k, Version: version, Granted: true})
	}
}

var docName = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// legalDoc serves a generated policy document (Markdown as plain text) such as /legal/privacy or /legal/pd-consent.
func (s *Server) legalDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("doc")
	if Policy.LegalDir == "" || !docName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(Policy.LegalDir, name+".md"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}

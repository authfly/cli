package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends mail through Stalwart's SMTP service. Dev: port 25 delivery to a local domain without AUTH.
// Production: submission (587 STARTTLS or 465 implicit TLS) with the credentials of a sender account.
type Mailer struct {
	Addr     string // host:port
	From     string
	FromName string
	User     string
	Pass     string
	TLS      bool   // implicit TLS (465)
	Insecure bool   // accept self-signed certificates (dev only)
	Helo     string // EHLO name; default: the domain of From (Stalwart rejects "localhost")
}

// Enabled reports whether outbound mail is configured (SMTP_ADDR set).
func (m *Mailer) Enabled() bool {
	return m != nil && strings.TrimSpace(m.Addr) != ""
}

// Send sends a plain-text message.
func (m *Mailer) Send(to, subject, body string) error {
	host, _, _ := net.SplitHostPort(m.Addr)
	msg := strings.Join([]string{
		"From: " + fmt.Sprintf("%q <%s>", m.FromName, m.From),
		"To: " + to,
		"Subject: " + subject,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + RandomString(12) + "@" + domainOf(m.From) + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"", body, ""}, "\r\n")
	var c *smtp.Client
	var err error
	tcfg := &tls.Config{ServerName: host, InsecureSkipVerify: m.Insecure}
	if m.TLS {
		conn, e := tls.Dial("tcp", m.Addr, tcfg)
		if e != nil {
			return e
		}
		c, err = smtp.NewClient(conn, host)
	} else {
		c, err = smtp.Dial(m.Addr)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	helo := m.Helo
	if helo == "" {
		helo = domainOf(m.From)
	}
	if err := c.Hello(helo); err != nil {
		return err
	}
	if !m.TLS {
		if ok, _ := c.Extension("STARTTLS"); ok && m.User != "" {
			if err := c.StartTLS(tcfg); err != nil {
				return err
			}
		}
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Pass, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return "localhost"
}

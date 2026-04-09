// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	htmltpl "html/template"
	"mime"
	"net"
	"net/smtp"
	"strings"
	texttpl "text/template"
	"time"

	"git.techniverse.net/scriptos/keywarden/internal/config"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
)

// LoginNotificationData holds the template data for a login notification email
type LoginNotificationData struct {
	Username  string
	IPAddress string
	Timestamp string
	UserAgent string
}

// InvitationData holds the template data for an invitation email
type InvitationData struct {
	Username  string
	InviteURL string
	ExpiresIn string
}

// Service handles email sending
type Service struct {
	cfg     *config.Config
	enabled bool
}

// NewService creates a new mail service
func NewService(cfg *config.Config) *Service {
	enabled := cfg.SMTPEnabled && cfg.SMTPHost != ""
	if enabled {
		logging.Info("Email notifications enabled (SMTP: %s:%s)", cfg.SMTPHost, cfg.SMTPPort)
	} else {
		logging.Info("Email notifications disabled (no SMTP host configured)")
	}
	return &Service{
		cfg:     cfg,
		enabled: enabled,
	}
}

// IsEnabled returns whether the mail service is configured and active
func (s *Service) IsEnabled() bool {
	return s.enabled
}

// SendLoginNotification sends a login notification email to the user.
// This runs synchronously but callers should invoke it in a goroutine.
func (s *Service) SendLoginNotification(toEmail string, data LoginNotificationData) error {
	if !s.enabled {
		return nil
	}

	htmlBody, err := renderHTMLTemplate(loginNotificationHTML, data)
	if err != nil {
		return fmt.Errorf("failed to render HTML template: %w", err)
	}

	txtBody, err := renderTemplate(loginNotificationTXT, data)
	if err != nil {
		return fmt.Errorf("failed to render TXT template: %w", err)
	}

	subject := fmt.Sprintf("Keywarden: Login notification for %s", data.Username)
	return s.sendMultipart(toEmail, subject, txtBody, htmlBody)
}

// SendTestEmail sends a test email to verify SMTP configuration
func (s *Service) SendTestEmail(toEmail string) error {
	if !s.enabled {
		return fmt.Errorf("email is not configured (KEYWARDEN_SMTP_HOST not set)")
	}

	subject := "Keywarden: SMTP Test Email"
	txtBody := "This is a test email from Keywarden.\n\nIf you received this, your SMTP configuration is working correctly.\n"
	htmlBody := `<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f1f5f9;">
<div style="max-width: 500px; margin: 0 auto; background: #ffffff; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
  <h2 style="color: #206bc4; margin-top: 0;">&#x1F511; Keywarden – SMTP Test</h2>
  <p>This is a test email from Keywarden.</p>
  <p style="color: #4caf50; font-weight: bold;">&#x2705; Your SMTP configuration is working correctly.</p>
</div>
</body>
</html>`

	return s.sendMultipart(toEmail, subject, txtBody, htmlBody)
}

// SendInvitation sends an invitation email with a registration link to a new user.
func (s *Service) SendInvitation(toEmail string, data InvitationData) error {
	if !s.enabled {
		return fmt.Errorf("email is not configured (KEYWARDEN_SMTP_HOST not set)")
	}

	htmlBody, err := renderHTMLTemplate(invitationHTML, data)
	if err != nil {
		return fmt.Errorf("failed to render invitation HTML template: %w", err)
	}

	txtBody, err := renderTemplate(invitationTXT, data)
	if err != nil {
		return fmt.Errorf("failed to render invitation TXT template: %w", err)
	}

	subject := fmt.Sprintf("Keywarden: You have been invited – %s", data.Username)
	return s.sendMultipart(toEmail, subject, txtBody, htmlBody)
}

// sendMultipart sends a multipart (text + HTML) email
func (s *Service) sendMultipart(to, subject, textBody, htmlBody string) error {
	logging.Info("Sending email: to=%s subject='%s' smtp=%s:%s", to, subject, s.cfg.SMTPHost, s.cfg.SMTPPort)
	logging.Debug("Email details: from=%s tls=%v", s.cfg.SMTPFrom, s.cfg.SMTPTLS)

	boundary := fmt.Sprintf("keywarden-%d", time.Now().UnixNano())

	// Encode Subject per RFC 2047 so non-ASCII characters (e.g. en-dash)
	// are transmitted safely through all MTAs.
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)

	headers := map[string]string{
		"From":         s.cfg.SMTPFrom,
		"To":           to,
		"Subject":      encodedSubject,
		"MIME-Version": "1.0",
		"Content-Type": fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary),
		"Date":         time.Now().Format(time.RFC1123Z),
		"X-Mailer":     "Keywarden SSH Key Management",
	}

	var msg bytes.Buffer
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")

	// Text part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(textBody)
	msg.WriteString("\r\n")

	// HTML part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	err := s.send(to, msg.Bytes())
	if err != nil {
		logging.Error("Email delivery failed: to=%s error=%v", to, err)
	} else {
		logging.Info("Email delivered successfully: to=%s", to)
	}
	return err
}

// send delivers a raw email message via SMTP
func (s *Service) send(to string, msg []byte) error {
	addr := net.JoinHostPort(s.cfg.SMTPHost, s.cfg.SMTPPort)

	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	if s.cfg.SMTPTLS {
		// STARTTLS or implicit TLS
		tlsConfig := &tls.Config{
			ServerName: s.cfg.SMTPHost,
			MinVersion: tls.VersionTLS12,
		}

		// Try implicit TLS first (port 465), fall back to STARTTLS
		if s.cfg.SMTPPort == "465" {
			conn, err := tls.Dial("tcp", addr, tlsConfig)
			if err != nil {
				return fmt.Errorf("TLS dial failed: %w", err)
			}
			defer conn.Close()

			client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
			if err != nil {
				return fmt.Errorf("SMTP client creation failed: %w", err)
			}
			defer client.Close()

			if auth != nil {
				if err := client.Auth(auth); err != nil {
					return fmt.Errorf("SMTP auth failed: %w", err)
				}
			}

			if err := client.Mail(s.cfg.SMTPFrom); err != nil {
				return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
			}
			if err := client.Rcpt(to); err != nil {
				return fmt.Errorf("SMTP RCPT TO failed: %w", err)
			}

			w, err := client.Data()
			if err != nil {
				return fmt.Errorf("SMTP DATA failed: %w", err)
			}
			if _, err := w.Write(msg); err != nil {
				return fmt.Errorf("SMTP write failed: %w", err)
			}
			if err := w.Close(); err != nil {
				return fmt.Errorf("SMTP close data failed: %w", err)
			}

			return client.Quit()
		}

		// STARTTLS (port 587 etc.)
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
		if err != nil {
			return fmt.Errorf("SMTP client creation failed: %w", err)
		}
		defer client.Close()

		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}

		if err := client.Mail(s.cfg.SMTPFrom); err != nil {
			return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
		}
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO failed: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA failed: %w", err)
		}
		if _, err := w.Write(msg); err != nil {
			return fmt.Errorf("SMTP write failed: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("SMTP close data failed: %w", err)
		}

		return client.Quit()
	}

	// Plain SMTP (no TLS) – use manual client to avoid Go's smtp.SendMail
	// automatically attempting STARTTLS when the server advertises it.
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(s.cfg.SMTPFrom); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP close data failed: %w", err)
	}

	return client.Quit()
}

func renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := texttpl.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// renderHTMLTemplate uses html/template for proper context-aware escaping,
// preventing XSS in HTML email bodies when user-supplied data is included.
func renderHTMLTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := htmltpl.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// --- Email Templates ---

var loginNotificationHTML = strings.TrimSpace(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; margin: 0; padding: 0; background-color: #f1f5f9; -webkit-font-smoothing: antialiased;">
  <div style="max-width: 600px; margin: 0 auto; padding: 24px;">
    <!-- Header -->
    <div style="background: linear-gradient(135deg, #206bc4 0%, #1a56a0 100%); border-radius: 12px 12px 0 0; padding: 32px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 24px;">&#x1F511; Keywarden</h1>
      <p style="color: rgba(255,255,255,0.8); margin: 8px 0 0; font-size: 14px;">Centralized SSH Key Management and Deployment</p>
    </div>

    <!-- Body -->
    <div style="background: #ffffff; padding: 32px; border-radius: 0 0 12px 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <h2 style="color: #1e293b; margin-top: 0; font-size: 20px;">Login Notification</h2>
      <p style="color: #475569; line-height: 1.6;">
        A successful login to your Keywarden account was detected:
      </p>

      <table style="width: 100%; border-collapse: collapse; margin: 24px 0;">
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155; width: 140px;">User</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.Username}}</td>
        </tr>
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155;">IP Address</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.IPAddress}}</td>
        </tr>
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155;">Time</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.Timestamp}}</td>
        </tr>
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155;">Browser</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.UserAgent}}</td>
        </tr>
      </table>

      <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 16px; margin: 24px 0;">
        <p style="margin: 0; color: #856404; font-size: 14px;">
          &#x26A0;&#xFE0F; <strong>If this was not you</strong>, please change your password immediately and review your account security settings.
        </p>
      </div>

      <p style="color: #94a3b8; font-size: 12px; margin-bottom: 0;">
        You received this email because login notifications are enabled for your account. You can disable them in the Settings page.
      </p>
    </div>

    <!-- Footer -->
    <div style="text-align: center; padding: 16px; color: #94a3b8; font-size: 12px;">
      &copy; 2026 Keywarden &ndash; Centralized SSH Key Management and Deployment
    </div>
  </div>
</body>
</html>
`)

var loginNotificationTXT = strings.TrimSpace(`
Keywarden - Login Notification
============================

A successful login to your Keywarden account was detected:

  User:       {{.Username}}
  IP Address: {{.IPAddress}}
  Time:       {{.Timestamp}}
  Browser:    {{.UserAgent}}

If this was not you, please change your password immediately
and review your account security settings.

--
You received this email because login notifications are enabled
for your account. You can disable them in the Settings page.

Keywarden - Centralized SSH Key Management and Deployment
`)

var invitationHTML = strings.TrimSpace(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; margin: 0; padding: 0; background-color: #f1f5f9; -webkit-font-smoothing: antialiased;">
  <div style="max-width: 600px; margin: 0 auto; padding: 24px;">
    <!-- Header -->
    <div style="background: linear-gradient(135deg, #206bc4 0%, #1a56a0 100%); border-radius: 12px 12px 0 0; padding: 32px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 24px;">&#x1F511; Keywarden</h1>
      <p style="color: rgba(255,255,255,0.8); margin: 8px 0 0; font-size: 14px;">Centralized SSH Key Management and Deployment</p>
    </div>

    <!-- Body -->
    <div style="background: #ffffff; padding: 32px; border-radius: 0 0 12px 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <h2 style="color: #1e293b; margin-top: 0; font-size: 20px;">You have been invited!</h2>
      <p style="color: #475569; line-height: 1.6;">
        An account has been created for you in Keywarden. Please complete your registration by setting a password.
      </p>

      <table style="width: 100%; border-collapse: collapse; margin: 24px 0;">
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155; width: 140px;">Username</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.Username}}</td>
        </tr>
        <tr>
          <td style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; font-weight: 600; color: #334155;">Valid for</td>
          <td style="padding: 12px 16px; border: 1px solid #e2e8f0; color: #475569;">{{.ExpiresIn}}</td>
        </tr>
      </table>

      <div style="text-align: center; margin: 32px 0;">
        <a href="{{.InviteURL}}" style="display: inline-block; background: #206bc4; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 16px;">
          &#x1F680; Complete Registration
        </a>
      </div>

      <div style="background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 8px; padding: 16px; margin: 24px 0;">
        <p style="margin: 0; color: #0369a1; font-size: 14px;">
          &#x1F6C8; If the button does not work, copy and paste this link into your browser:
        </p>
        <p style="margin: 8px 0 0; color: #0369a1; font-size: 12px; word-break: break-all;">{{.InviteURL}}</p>
      </div>

      <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 16px; margin: 24px 0;">
        <p style="margin: 0; color: #856404; font-size: 14px;">
          &#x26A0;&#xFE0F; <strong>This link is valid for {{.ExpiresIn}} and can only be used once.</strong> If you did not expect this invitation, you can safely ignore this email.
        </p>
      </div>

      <p style="color: #94a3b8; font-size: 12px; margin-bottom: 0;">
        This is an automated invitation from Keywarden.
      </p>
    </div>

    <!-- Footer -->
    <div style="text-align: center; padding: 16px; color: #94a3b8; font-size: 12px;">
      &copy; 2026 Keywarden &ndash; Centralized SSH Key Management and Deployment
    </div>
  </div>
</body>
</html>
`)

var invitationTXT = strings.TrimSpace(`
Keywarden - Invitation
======================

You have been invited to Keywarden!

An account has been created for you. Please complete your registration
by setting a password.

  Username:  {{.Username}}
  Valid for: {{.ExpiresIn}}

Complete your registration here:
  {{.InviteURL}}

This link is valid for {{.ExpiresIn}} and can only be used once.
If you did not expect this invitation, you can safely ignore this email.

--
Keywarden - Centralized SSH Key Management and Deployment
`)

package notification

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultEmailProviderName = "DDH_SMTP"
	defaultEmailFromName     = "Digital Defense Hub"
	defaultEmailSubject      = "[DDH]"
	defaultEmailTimeout      = 30 * time.Second
)

// EmailProviderConfig contains SMTP configuration.
//
// UseImplicitTLS is normally used with port 465.
// RequireSTARTTLS is normally used with port 587.
type EmailProviderConfig struct {
	ProviderName string

	Host string
	Port int

	Username string
	Password string

	FromAddress   string
	FromName      string
	SubjectPrefix string

	UseImplicitTLS        bool
	RequireSTARTTLS       bool
	TLSInsecureSkipVerify bool

	Timeout time.Duration
}

// EmailProvider delivers notification messages through an SMTP server.
type EmailProvider struct {
	config EmailProviderConfig
}

func NewEmailProvider(
	config EmailProviderConfig,
) (*EmailProvider, error) {
	config.ProviderName = strings.TrimSpace(
		config.ProviderName,
	)
	config.Host = strings.TrimSpace(
		config.Host,
	)
	config.Username = strings.TrimSpace(
		config.Username,
	)
	config.FromAddress = strings.TrimSpace(
		config.FromAddress,
	)
	config.FromName = sanitizeEmailHeader(
		config.FromName,
	)
	config.SubjectPrefix = sanitizeEmailHeader(
		config.SubjectPrefix,
	)

	if config.ProviderName == "" {
		config.ProviderName = defaultEmailProviderName
	}

	if config.Host == "" {
		return nil, errors.New(
			"SMTP host is required",
		)
	}

	if config.Port == 0 {
		if config.UseImplicitTLS {
			config.Port = 465
		} else {
			config.Port = 587
		}
	}

	if config.Port < 1 || config.Port > 65535 {
		return nil, errors.New(
			"SMTP port must be between 1 and 65535",
		)
	}

	if config.FromAddress == "" {
		return nil, errors.New(
			"SMTP from address is required",
		)
	}

	fromAddress, err := mail.ParseAddress(
		config.FromAddress,
	)
	if err != nil || strings.TrimSpace(fromAddress.Address) == "" {
		return nil, errors.New(
			"SMTP from address is invalid",
		)
	}

	config.FromAddress = fromAddress.Address

	if config.FromName == "" {
		config.FromName = defaultEmailFromName
	}

	if config.SubjectPrefix == "" {
		config.SubjectPrefix = defaultEmailSubject
	}

	if config.UseImplicitTLS &&
		config.RequireSTARTTLS {
		return nil, errors.New(
			"SMTP implicit TLS and STARTTLS cannot both be enabled",
		)
	}

	usernameConfigured := config.Username != ""
	passwordConfigured := config.Password != ""

	if usernameConfigured != passwordConfigured {
		return nil, errors.New(
			"SMTP username and password must be configured together",
		)
	}

	if config.Timeout <= 0 {
		config.Timeout = defaultEmailTimeout
	}

	return &EmailProvider{
		config: config,
	}, nil
}

func (p *EmailProvider) Name() string {
	return p.config.ProviderName
}

func (p *EmailProvider) Channel() string {
	return "EMAIL"
}

func (p *EmailProvider) Send(
	ctx context.Context,
	message DeliveryMessage,
) (*ProviderResult, error) {
	if err := ValidateDeliveryMessage(message); err != nil {
		return nil, fmt.Errorf(
			"validate email delivery message: %w",
			err,
		)
	}

	if message.Delivery.Channel != p.Channel() {
		return nil, fmt.Errorf(
			"email provider cannot process %s channel",
			message.Delivery.Channel,
		)
	}

	if message.Recipient.EmailAddress == nil ||
		strings.TrimSpace(
			*message.Recipient.EmailAddress,
		) == "" {
		return nil, errors.New(
			"email recipient address is required",
		)
	}

	recipientAddress, err := mail.ParseAddress(
		strings.TrimSpace(
			*message.Recipient.EmailAddress,
		),
	)
	if err != nil ||
		strings.TrimSpace(recipientAddress.Address) == "" {
		return nil, errors.New(
			"email recipient address is invalid",
		)
	}

	messageID := buildEmailMessageID(
		message.Delivery.ID.String(),
		p.config.Host,
	)

	emailContent := p.buildEmailContent(
		message,
		recipientAddress.Address,
		messageID,
	)

	if err = p.sendSMTPMessage(
		ctx,
		recipientAddress.Address,
		emailContent,
	); err != nil {
		return nil, fmt.Errorf(
			"send SMTP notification: %w",
			err,
		)
	}

	acceptedAt := time.Now().UTC()

	providerResponse, err := json.Marshal(
		map[string]any{
			"status":            "ACCEPTED",
			"provider":          p.Name(),
			"channel":           p.Channel(),
			"message_id":        messageID,
			"notification_code": message.Notification.NotificationCode,
			"delivery_id":       message.Delivery.ID.String(),
			"smtp_host":         p.config.Host,
			"smtp_port":         p.config.Port,
			"accepted_at":       acceptedAt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode SMTP provider response: %w",
			err,
		)
	}

	// SMTP acceptance confirms that the mail server accepted the message.
	// It does not guarantee final mailbox delivery, so Delivered remains false.
	return &ProviderResult{
		ProviderName:      p.Name(),
		ProviderMessageID: &messageID,
		ProviderResponse:  providerResponse,
		Delivered:         false,
		SentAt:            &acceptedAt,
	}, nil
}

func (p *EmailProvider) sendSMTPMessage(
	ctx context.Context,
	recipientAddress string,
	content []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	serverAddress := net.JoinHostPort(
		p.config.Host,
		strconv.Itoa(p.config.Port),
	)

	dialer := &net.Dialer{
		Timeout: p.config.Timeout,
	}

	rawConnection, err := dialer.DialContext(
		ctx,
		"tcp",
		serverAddress,
	)
	if err != nil {
		return fmt.Errorf(
			"connect to SMTP server: %w",
			err,
		)
	}

	connection := rawConnection
	connectionEncrypted := false

	deadline := time.Now().Add(
		p.config.Timeout,
	)

	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	if err = connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()

		return fmt.Errorf(
			"set SMTP connection deadline: %w",
			err,
		)
	}

	tlsConfig := &tls.Config{
		ServerName:         p.config.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.config.TLSInsecureSkipVerify,
	}

	if p.config.UseImplicitTLS {
		tlsConnection := tls.Client(
			rawConnection,
			tlsConfig,
		)

		if err = tlsConnection.HandshakeContext(ctx); err != nil {
			_ = rawConnection.Close()

			return fmt.Errorf(
				"perform SMTP TLS handshake: %w",
				err,
			)
		}

		connection = tlsConnection
		connectionEncrypted = true
	}

	defer func() {
		_ = connection.Close()
	}()

	client, err := smtp.NewClient(
		connection,
		p.config.Host,
	)
	if err != nil {
		return fmt.Errorf(
			"create SMTP client: %w",
			err,
		)
	}

	defer func() {
		_ = client.Close()
	}()

	if !p.config.UseImplicitTLS {
		startTLSSupported, _ := client.Extension(
			"STARTTLS",
		)

		if startTLSSupported {
			if err = client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf(
					"start SMTP TLS session: %w",
					err,
				)
			}

			connectionEncrypted = true
		} else if p.config.RequireSTARTTLS {
			return errors.New(
				"SMTP server does not support required STARTTLS",
			)
		}
	}

	if p.config.Username != "" {
		if !connectionEncrypted {
			return errors.New(
				"SMTP authentication cannot be used without TLS",
			)
		}

		auth := smtp.PlainAuth(
			"",
			p.config.Username,
			p.config.Password,
			p.config.Host,
		)

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf(
				"authenticate with SMTP server: %w",
				err,
			)
		}
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	if err = client.Mail(p.config.FromAddress); err != nil {
		return fmt.Errorf(
			"set SMTP sender: %w",
			err,
		)
	}

	if err = client.Rcpt(recipientAddress); err != nil {
		return fmt.Errorf(
			"set SMTP recipient: %w",
			err,
		)
	}

	dataWriter, err := client.Data()
	if err != nil {
		return fmt.Errorf(
			"start SMTP message body: %w",
			err,
		)
	}

	if _, err = dataWriter.Write(content); err != nil {
		_ = dataWriter.Close()

		return fmt.Errorf(
			"write SMTP message body: %w",
			err,
		)
	}

	if err = dataWriter.Close(); err != nil {
		return fmt.Errorf(
			"complete SMTP message body: %w",
			err,
		)
	}

	// The server already accepted the message when Data.Close succeeded.
	// QUIT failure therefore does not change the delivery result.
	_ = client.Quit()

	return nil
}

func (p *EmailProvider) buildEmailContent(
	message DeliveryMessage,
	recipientAddress string,
	messageID string,
) []byte {
	fromHeader := (&mail.Address{
		Name:    p.config.FromName,
		Address: p.config.FromAddress,
	}).String()

	recipientName := ""

	if message.Recipient.RecipientName != nil {
		recipientName = sanitizeEmailHeader(
			*message.Recipient.RecipientName,
		)
	}

	toHeader := (&mail.Address{
		Name:    recipientName,
		Address: recipientAddress,
	}).String()

	subject := strings.TrimSpace(
		p.config.SubjectPrefix +
			" [" +
			sanitizeEmailHeader(
				message.Notification.Severity,
			) +
			"] " +
			sanitizeEmailHeader(
				message.Notification.Title,
			),
	)

	encodedSubject := mime.QEncoding.Encode(
		"UTF-8",
		subject,
	)

	body := buildEmailBody(message)

	var builder strings.Builder

	writeEmailHeader(
		&builder,
		"Date",
		time.Now().UTC().Format(time.RFC1123Z),
	)
	writeEmailHeader(
		&builder,
		"From",
		fromHeader,
	)
	writeEmailHeader(
		&builder,
		"To",
		toHeader,
	)
	writeEmailHeader(
		&builder,
		"Subject",
		encodedSubject,
	)
	writeEmailHeader(
		&builder,
		"Message-ID",
		messageID,
	)
	writeEmailHeader(
		&builder,
		"MIME-Version",
		"1.0",
	)
	writeEmailHeader(
		&builder,
		"Content-Type",
		`text/plain; charset="UTF-8"`,
	)
	writeEmailHeader(
		&builder,
		"Content-Transfer-Encoding",
		"8bit",
	)

	builder.WriteString("\r\n")
	builder.WriteString(normalizeEmailBody(body))

	return []byte(builder.String())
}

func buildEmailBody(
	message DeliveryMessage,
) string {
	var builder strings.Builder

	builder.WriteString(
		"Digital Defense Hub Security Notification\n\n",
	)

	builder.WriteString("Notification Code: ")
	builder.WriteString(
		message.Notification.NotificationCode,
	)
	builder.WriteString("\n")

	builder.WriteString("Severity: ")
	builder.WriteString(
		message.Notification.Severity,
	)
	builder.WriteString("\n")

	builder.WriteString("Category: ")
	builder.WriteString(
		message.Notification.Category,
	)
	builder.WriteString("\n")

	builder.WriteString("Type: ")
	builder.WriteString(
		message.Notification.NotificationType,
	)
	builder.WriteString("\n")

	builder.WriteString("Title: ")
	builder.WriteString(
		message.Notification.Title,
	)
	builder.WriteString("\n\n")

	builder.WriteString("Message:\n")
	builder.WriteString(
		message.Notification.Message,
	)
	builder.WriteString("\n")

	if message.Notification.RequiresAcknowledgement {
		builder.WriteString(
			"\nAcknowledgement is required for this notification.\n",
		)
	}

	builder.WriteString(
		"\nThis notification was generated automatically by Digital Defense Hub.\n",
	)

	return builder.String()
}

func writeEmailHeader(
	writer io.StringWriter,
	name string,
	value string,
) {
	_, _ = writer.WriteString(
		sanitizeEmailHeader(name),
	)
	_, _ = writer.WriteString(": ")
	_, _ = writer.WriteString(
		sanitizeEmailHeader(value),
	)
	_, _ = writer.WriteString("\r\n")
}

func sanitizeEmailHeader(
	value string,
) string {
	value = strings.ReplaceAll(
		value,
		"\r",
		" ",
	)
	value = strings.ReplaceAll(
		value,
		"\n",
		" ",
	)

	return strings.TrimSpace(value)
}

func normalizeEmailBody(
	value string,
) string {
	value = strings.ReplaceAll(
		value,
		"\r\n",
		"\n",
	)
	value = strings.ReplaceAll(
		value,
		"\r",
		"\n",
	)

	return strings.ReplaceAll(
		value,
		"\n",
		"\r\n",
	)
}

func buildEmailMessageID(
	deliveryID string,
	host string,
) string {
	deliveryID = strings.TrimSpace(
		deliveryID,
	)

	host = strings.TrimSpace(host)
	host = strings.ReplaceAll(host, " ", "")
	host = strings.ReplaceAll(host, "\r", "")
	host = strings.ReplaceAll(host, "\n", "")

	return fmt.Sprintf(
		"<%s@%s>",
		deliveryID,
		host,
	)
}

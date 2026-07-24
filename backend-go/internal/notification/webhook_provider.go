package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultWebhookProviderName = "DDH_WEBHOOK"
	defaultWebhookTimeout      = 20 * time.Second
	defaultWebhookResponseSize = 65536
)

type WebhookProviderConfig struct {
	ProviderName string
	EndpointURL  string
	Secret       string

	SignatureHeader string
	TimestampHeader string

	AllowInsecureHTTP   bool
	Timeout             time.Duration
	MaximumResponseSize int64

	AdditionalHeaders map[string]string
}

type WebhookProvider struct {
	config   WebhookProviderConfig
	endpoint *url.URL
	client   *http.Client
}

type webhookDeliveryEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	GeneratedAt   time.Time `json:"generated_at"`

	Delivery  webhookDeliveryDetails `json:"delivery"`
	Recipient webhookRecipient       `json:"recipient"`

	Notification webhookNotification `json:"notification"`
}

type webhookDeliveryDetails struct {
	ID      string `json:"id"`
	Channel string `json:"channel"`
}

type webhookRecipient struct {
	ID            string  `json:"id"`
	RecipientType string  `json:"recipient_type"`
	UserID        *string `json:"user_id,omitempty"`
	RecipientName *string `json:"recipient_name,omitempty"`
	EmailAddress  *string `json:"email_address,omitempty"`
	PhoneNumber   *string `json:"phone_number,omitempty"`
}

type webhookNotification struct {
	ID                      string          `json:"id"`
	NotificationSequence    int64           `json:"notification_sequence"`
	NotificationCode        string          `json:"notification_code"`
	OrganizationID          string          `json:"organization_id"`
	DepartmentID            *string         `json:"department_id,omitempty"`
	IncidentID              *string         `json:"incident_id,omitempty"`
	ThreatID                *string         `json:"threat_id,omitempty"`
	NotificationType        string          `json:"notification_type"`
	Category                string          `json:"category"`
	Title                   string          `json:"title"`
	Message                 string          `json:"message"`
	Severity                string          `json:"severity"`
	PriorityLevel           int             `json:"priority_level"`
	Payload                 json.RawMessage `json:"payload"`
	RequiresAcknowledgement bool            `json:"requires_acknowledgement"`
	ScheduledAt             *time.Time      `json:"scheduled_at,omitempty"`
	ExpiresAt               *time.Time      `json:"expires_at,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
}

type WebhookProviderHTTPError struct {
	StatusCode int
	Status     string
	Response   string
}

func (e *WebhookProviderHTTPError) Error() string {
	if e == nil {
		return "webhook request failed"
	}

	if strings.TrimSpace(e.Response) == "" {
		return fmt.Sprintf(
			"webhook endpoint returned %s",
			e.Status,
		)
	}

	return fmt.Sprintf(
		"webhook endpoint returned %s: %s",
		e.Status,
		e.Response,
	)
}

func (e *WebhookProviderHTTPError) Temporary() bool {
	if e == nil {
		return false
	}

	return e.StatusCode == http.StatusRequestTimeout ||
		e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= http.StatusInternalServerError
}

func NewWebhookProvider(
	config WebhookProviderConfig,
) (*WebhookProvider, error) {
	config.ProviderName = strings.TrimSpace(
		config.ProviderName,
	)
	config.EndpointURL = strings.TrimSpace(
		config.EndpointURL,
	)
	config.Secret = strings.TrimSpace(
		config.Secret,
	)
	config.SignatureHeader = strings.TrimSpace(
		config.SignatureHeader,
	)
	config.TimestampHeader = strings.TrimSpace(
		config.TimestampHeader,
	)

	if config.ProviderName == "" {
		config.ProviderName =
			defaultWebhookProviderName
	}

	if config.EndpointURL == "" {
		return nil, errors.New(
			"webhook endpoint URL is required",
		)
	}

	endpoint, err := url.ParseRequestURI(
		config.EndpointURL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"webhook endpoint URL is invalid: %w",
			err,
		)
	}

	if endpoint.Scheme != "https" &&
		endpoint.Scheme != "http" {
		return nil, errors.New(
			"webhook endpoint must use HTTP or HTTPS",
		)
	}

	if endpoint.Host == "" {
		return nil, errors.New(
			"webhook endpoint host is required",
		)
	}

	if endpoint.Scheme == "http" &&
		!config.AllowInsecureHTTP {
		return nil, errors.New(
			"webhook HTTP connection is disabled; use HTTPS or explicitly allow insecure HTTP",
		)
	}

	if len(config.Secret) < 32 {
		return nil, errors.New(
			"webhook signing secret must contain at least 32 characters",
		)
	}

	if config.SignatureHeader == "" {
		config.SignatureHeader =
			"X-DDH-Signature"
	}

	if config.TimestampHeader == "" {
		config.TimestampHeader =
			"X-DDH-Timestamp"
	}

	if config.Timeout <= 0 {
		config.Timeout = defaultWebhookTimeout
	}

	if config.MaximumResponseSize <= 0 {
		config.MaximumResponseSize =
			defaultWebhookResponseSize
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New(
			"default HTTP transport is unavailable",
		)
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport.Clone(),
		CheckRedirect: func(
			request *http.Request,
			previousRequests []*http.Request,
		) error {
			if len(previousRequests) >= 3 {
				return errors.New(
					"webhook redirect limit exceeded",
				)
			}

			if len(previousRequests) > 0 {
				previousRequest :=
					previousRequests[len(previousRequests)-1]

				if previousRequest.URL.Scheme == "https" &&
					request.URL.Scheme != "https" {
					return errors.New(
						"webhook HTTPS downgrade redirect rejected",
					)
				}
			}

			return nil
		},
	}

	return &WebhookProvider{
		config:   config,
		endpoint: endpoint,
		client:   client,
	}, nil
}

func (p *WebhookProvider) Name() string {
	return p.config.ProviderName
}

func (p *WebhookProvider) Channel() string {
	return "WEBHOOK"
}

func (p *WebhookProvider) Send(
	ctx context.Context,
	message DeliveryMessage,
) (*ProviderResult, error) {
	if err := ValidateDeliveryMessage(message); err != nil {
		return nil, fmt.Errorf(
			"validate webhook delivery message: %w",
			err,
		)
	}

	if message.Delivery.Channel != p.Channel() {
		return nil, fmt.Errorf(
			"webhook provider cannot process %s channel",
			message.Delivery.Channel,
		)
	}

	generatedAt := time.Now().UTC()

	envelope := webhookDeliveryEnvelope{
		SchemaVersion: 1,
		EventID:       message.Delivery.ID.String(),
		EventType:     message.Notification.NotificationType,
		GeneratedAt:   generatedAt,
		Delivery: webhookDeliveryDetails{
			ID:      message.Delivery.ID.String(),
			Channel: message.Delivery.Channel,
		},
		Recipient: webhookRecipient{
			ID:            message.Recipient.ID.String(),
			RecipientType: message.Recipient.RecipientType,
			UserID:        webhookOptionalUUID(message.Recipient.UserID),
			RecipientName: normalizeWebhookOptionalString(message.Recipient.RecipientName),
			EmailAddress:  normalizeWebhookOptionalString(message.Recipient.EmailAddress),
			PhoneNumber:   normalizeWebhookOptionalString(message.Recipient.PhoneNumber),
		},
		Notification: webhookNotification{
			ID:                      message.Notification.ID.String(),
			NotificationSequence:    message.Notification.NotificationSequence,
			NotificationCode:        message.Notification.NotificationCode,
			OrganizationID:          message.Notification.OrganizationID.String(),
			DepartmentID:            webhookOptionalUUID(message.Notification.DepartmentID),
			IncidentID:              webhookOptionalUUID(message.Notification.IncidentID),
			ThreatID:                webhookOptionalUUID(message.Notification.ThreatID),
			NotificationType:        message.Notification.NotificationType,
			Category:                message.Notification.Category,
			Title:                   message.Notification.Title,
			Message:                 message.Notification.Message,
			Severity:                message.Notification.Severity,
			PriorityLevel:           message.Notification.PriorityLevel,
			Payload:                 normalizeWebhookPayload(message.Notification.Payload),
			RequiresAcknowledgement: message.Notification.RequiresAcknowledgement,
			ScheduledAt:             message.Notification.ScheduledAt,
			ExpiresAt:               message.Notification.ExpiresAt,
			CreatedAt:               message.Notification.CreatedAt,
		},
	}

	encodedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf(
			"encode webhook payload: %w",
			err,
		)
	}

	timestamp := strconv.FormatInt(
		generatedAt.Unix(),
		10,
	)

	signature := generateWebhookSignature(
		p.config.Secret,
		timestamp,
		encodedEnvelope,
	)

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.endpoint.String(),
		bytes.NewReader(encodedEnvelope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create webhook request: %w",
			err,
		)
	}

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.Header.Set(
		"Accept",
		"application/json",
	)
	request.Header.Set(
		"User-Agent",
		"Digital-Defense-Hub/1.0",
	)
	request.Header.Set(
		"Idempotency-Key",
		message.Delivery.ID.String(),
	)
	request.Header.Set(
		"X-DDH-Event-ID",
		message.Delivery.ID.String(),
	)
	request.Header.Set(
		"X-DDH-Event-Type",
		message.Notification.NotificationType,
	)

	for headerName, headerValue := range p.config.AdditionalHeaders {
		headerName = strings.TrimSpace(headerName)
		headerValue = strings.TrimSpace(headerValue)

		if headerName == "" ||
			headerValue == "" {
			continue
		}

		if strings.EqualFold(headerName, "Host") ||
			strings.EqualFold(headerName, "Content-Length") ||
			strings.EqualFold(
				headerName,
				p.config.SignatureHeader,
			) ||
			strings.EqualFold(
				headerName,
				p.config.TimestampHeader,
			) {
			continue
		}

		request.Header.Set(
			headerName,
			headerValue,
		)
	}

	request.Header.Set(
		p.config.TimestampHeader,
		timestamp,
	)
	request.Header.Set(
		p.config.SignatureHeader,
		signature,
	)

	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"execute webhook request: %w",
			err,
		)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, truncated, err :=
		readWebhookResponse(
			response.Body,
			p.config.MaximumResponseSize,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"read webhook response: %w",
			err,
		)
	}

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return nil,
			&WebhookProviderHTTPError{
				StatusCode: response.StatusCode,
				Status:     response.Status,
				Response: strings.TrimSpace(
					string(responseBody),
				),
			}
	}

	deliveredAt := time.Now().UTC()

	providerResponse, err :=
		buildWebhookProviderResponse(
			response.StatusCode,
			response.Status,
			responseBody,
			truncated,
			deliveredAt,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode webhook provider response: %w",
			err,
		)
	}

	providerMessageID := message.Delivery.ID.String()

	return &ProviderResult{
		ProviderName:      p.Name(),
		ProviderMessageID: &providerMessageID,
		ProviderResponse:  providerResponse,
		Delivered:         true,
		SentAt:            &deliveredAt,
		DeliveredAt:       &deliveredAt,
	}, nil
}

func generateWebhookSignature(
	secret string,
	timestamp string,
	payload []byte,
) string {
	mac := hmac.New(
		sha256.New,
		[]byte(secret),
	)

	_, _ = mac.Write(
		[]byte(timestamp),
	)
	_, _ = mac.Write(
		[]byte("."),
	)
	_, _ = mac.Write(payload)

	return "sha256=" +
		hex.EncodeToString(mac.Sum(nil))
}

func readWebhookResponse(
	reader io.Reader,
	maximumSize int64,
) ([]byte, bool, error) {
	if maximumSize <= 0 {
		maximumSize =
			defaultWebhookResponseSize
	}

	responseBody, err := io.ReadAll(
		io.LimitReader(
			reader,
			maximumSize+1,
		),
	)
	if err != nil {
		return nil, false, err
	}

	if int64(len(responseBody)) <= maximumSize {
		return responseBody, false, nil
	}

	return responseBody[:maximumSize], true, nil
}

func buildWebhookProviderResponse(
	statusCode int,
	status string,
	responseBody []byte,
	truncated bool,
	deliveredAt time.Time,
) (json.RawMessage, error) {
	var endpointResponse any

	if len(bytes.TrimSpace(responseBody)) > 0 {
		if json.Valid(responseBody) {
			if err := json.Unmarshal(
				responseBody,
				&endpointResponse,
			); err != nil {
				return nil, err
			}
		} else {
			endpointResponse = strings.TrimSpace(
				string(responseBody),
			)
		}
	}

	encodedResponse, err := json.Marshal(
		map[string]any{
			"http_status_code":   statusCode,
			"http_status":        status,
			"endpoint_response":  endpointResponse,
			"response_truncated": truncated,
			"delivered_at":       deliveredAt,
		},
	)
	if err != nil {
		return nil, err
	}

	return encodedResponse, nil
}

func webhookOptionalUUID(
	value *uuid.UUID,
) *string {
	if value == nil ||
		*value == uuid.Nil {
		return nil
	}

	normalizedValue := value.String()

	return &normalizedValue
}

func normalizeWebhookOptionalString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.TrimSpace(
		*value,
	)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeWebhookPayload(
	payload json.RawMessage,
) json.RawMessage {
	if len(payload) == 0 ||
		!json.Valid(payload) {
		return json.RawMessage(`{}`)
	}

	return append(
		json.RawMessage(nil),
		payload...,
	)
}

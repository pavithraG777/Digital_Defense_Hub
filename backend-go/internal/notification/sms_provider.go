package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultSMSProviderName       = "DDH_HTTP_SMS"
	defaultSMSProviderTimeout    = 20 * time.Second
	defaultSMSMaximumMessageSize = 1200
	defaultSMSResponseSize       = 65536
)

type SMSProviderConfig struct {
	ProviderName string

	EndpointURL  string
	APIKey       string
	APIKeyHeader string
	APIKeyPrefix string

	FromNumber         string
	DefaultCountryCode string

	AllowInsecureHTTP   bool
	Timeout             time.Duration
	MaximumMessageSize  int
	MaximumResponseSize int64

	AdditionalHeaders map[string]string
}

type SMSProvider struct {
	config   SMSProviderConfig
	endpoint *url.URL
	client   *http.Client
}

type smsGatewayRequest struct {
	From             string `json:"from,omitempty"`
	To               string `json:"to"`
	Message          string `json:"message"`
	Reference        string `json:"reference"`
	NotificationCode string `json:"notification_code"`
	Severity         string `json:"severity"`
}

type SMSProviderHTTPError struct {
	StatusCode int
	Status     string
	Response   string
}

func (e *SMSProviderHTTPError) Error() string {
	if e == nil {
		return "SMS gateway request failed"
	}

	if strings.TrimSpace(e.Response) == "" {
		return fmt.Sprintf(
			"SMS gateway returned %s",
			e.Status,
		)
	}

	return fmt.Sprintf(
		"SMS gateway returned %s: %s",
		e.Status,
		e.Response,
	)
}

func (e *SMSProviderHTTPError) Temporary() bool {
	if e == nil {
		return false
	}

	return e.StatusCode == http.StatusRequestTimeout ||
		e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= http.StatusInternalServerError
}

func NewSMSProvider(
	config SMSProviderConfig,
) (*SMSProvider, error) {
	config.ProviderName = strings.TrimSpace(
		config.ProviderName,
	)
	config.EndpointURL = strings.TrimSpace(
		config.EndpointURL,
	)
	config.APIKey = strings.TrimSpace(
		config.APIKey,
	)
	config.APIKeyHeader = strings.TrimSpace(
		config.APIKeyHeader,
	)
	config.APIKeyPrefix = strings.TrimSpace(
		config.APIKeyPrefix,
	)
	config.FromNumber = strings.TrimSpace(
		config.FromNumber,
	)
	config.DefaultCountryCode = strings.TrimSpace(
		config.DefaultCountryCode,
	)

	if config.ProviderName == "" {
		config.ProviderName = defaultSMSProviderName
	}

	if config.EndpointURL == "" {
		return nil, errors.New(
			"SMS gateway endpoint URL is required",
		)
	}

	endpoint, err := url.ParseRequestURI(
		config.EndpointURL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"SMS gateway endpoint URL is invalid: %w",
			err,
		)
	}

	if endpoint.Scheme != "https" &&
		endpoint.Scheme != "http" {
		return nil, errors.New(
			"SMS gateway endpoint must use HTTP or HTTPS",
		)
	}

	if endpoint.Host == "" {
		return nil, errors.New(
			"SMS gateway endpoint host is required",
		)
	}

	if endpoint.Scheme == "http" &&
		!config.AllowInsecureHTTP {
		return nil, errors.New(
			"SMS gateway HTTP connection is disabled; use HTTPS or explicitly allow insecure HTTP",
		)
	}

	if config.APIKeyHeader == "" {
		config.APIKeyHeader = "Authorization"
	}

	if config.APIKey != "" &&
		config.APIKeyPrefix == "" &&
		strings.EqualFold(
			config.APIKeyHeader,
			"Authorization",
		) {
		config.APIKeyPrefix = "Bearer"
	}

	if config.Timeout <= 0 {
		config.Timeout = defaultSMSProviderTimeout
	}

	if config.MaximumMessageSize <= 0 {
		config.MaximumMessageSize =
			defaultSMSMaximumMessageSize
	}

	if config.MaximumResponseSize <= 0 {
		config.MaximumResponseSize =
			defaultSMSResponseSize
	}

	if config.DefaultCountryCode != "" {
		normalizedCountryCode, countryCodeErr :=
			normalizeSMSCountryCode(
				config.DefaultCountryCode,
			)
		if countryCodeErr != nil {
			return nil, countryCodeErr
		}

		config.DefaultCountryCode =
			normalizedCountryCode
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
					"SMS gateway redirect limit exceeded",
				)
			}

			if len(previousRequests) > 0 {
				previousRequest := previousRequests[len(previousRequests)-1]

				if previousRequest.URL.Scheme == "https" &&
					request.URL.Scheme != "https" {
					return errors.New(
						"SMS gateway HTTPS downgrade redirect rejected",
					)
				}
			}
			return nil
		},
	}

	return &SMSProvider{
		config:   config,
		endpoint: endpoint,
		client:   client,
	}, nil
}

func (p *SMSProvider) Name() string {
	return p.config.ProviderName
}

func (p *SMSProvider) Channel() string {
	return "SMS"
}

func (p *SMSProvider) Send(
	ctx context.Context,
	message DeliveryMessage,
) (*ProviderResult, error) {
	if err := ValidateDeliveryMessage(message); err != nil {
		return nil, fmt.Errorf(
			"validate SMS delivery message: %w",
			err,
		)
	}

	if message.Delivery.Channel != p.Channel() {
		return nil, fmt.Errorf(
			"SMS provider cannot process %s channel",
			message.Delivery.Channel,
		)
	}

	if message.Recipient.PhoneNumber == nil ||
		strings.TrimSpace(
			*message.Recipient.PhoneNumber,
		) == "" {
		return nil, errors.New(
			"SMS recipient phone number is required",
		)
	}

	phoneNumber, err := normalizeSMSPhoneNumber(
		*message.Recipient.PhoneNumber,
		p.config.DefaultCountryCode,
	)
	if err != nil {
		return nil, err
	}

	smsMessage := buildSMSNotificationMessage(
		message,
		p.config.MaximumMessageSize,
	)

	requestPayload := smsGatewayRequest{
		From:             p.config.FromNumber,
		To:               phoneNumber,
		Message:          smsMessage,
		Reference:        message.Delivery.ID.String(),
		NotificationCode: message.Notification.NotificationCode,
		Severity:         message.Notification.Severity,
	}

	encodedPayload, err := json.Marshal(
		requestPayload,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode SMS gateway request: %w",
			err,
		)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.endpoint.String(),
		bytes.NewReader(encodedPayload),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create SMS gateway request: %w",
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
		"Idempotency-Key",
		message.Delivery.ID.String(),
	)
	request.Header.Set(
		"X-DDH-Notification-Code",
		message.Notification.NotificationCode,
	)

	for headerName, headerValue := range p.config.AdditionalHeaders {
		headerName = strings.TrimSpace(headerName)
		headerValue = strings.TrimSpace(headerValue)

		if headerName == "" ||
			headerValue == "" {
			continue
		}

		if strings.EqualFold(
			headerName,
			"Host",
		) ||
			strings.EqualFold(
				headerName,
				"Content-Length",
			) {
			continue
		}

		request.Header.Set(
			headerName,
			headerValue,
		)
	}

	if p.config.APIKey != "" {
		credential := p.config.APIKey

		if p.config.APIKeyPrefix != "" {
			credential = p.config.APIKeyPrefix +
				" " +
				p.config.APIKey
		}

		request.Header.Set(
			p.config.APIKeyHeader,
			credential,
		)
	}

	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"execute SMS gateway request: %w",
			err,
		)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, responseTruncated, err :=
		readSMSProviderResponse(
			response.Body,
			p.config.MaximumResponseSize,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"read SMS gateway response: %w",
			err,
		)
	}

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return nil, &SMSProviderHTTPError{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Response: strings.TrimSpace(
				string(responseBody),
			),
		}
	}

	providerResponse, delivered, err :=
		buildSMSProviderResponse(
			response.StatusCode,
			response.Status,
			responseBody,
			responseTruncated,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode SMS provider response: %w",
			err,
		)
	}

	sentAt := time.Now().UTC()
	providerMessageID := message.Delivery.ID.String()

	var deliveredAt *time.Time

	if delivered {
		deliveredAt = &sentAt
	}

	return &ProviderResult{
		ProviderName:      p.Name(),
		ProviderMessageID: &providerMessageID,
		ProviderResponse:  providerResponse,
		Delivered:         delivered,
		SentAt:            &sentAt,
		DeliveredAt:       deliveredAt,
	}, nil
}

func buildSMSNotificationMessage(
	message DeliveryMessage,
	maximumLength int,
) string {
	parts := []string{
		"DDH",
		"[" + strings.TrimSpace(
			message.Notification.Severity,
		) + "]",
		strings.TrimSpace(
			message.Notification.Title,
		) + ":",
		strings.TrimSpace(
			message.Notification.Message,
		),
		"Code:",
		strings.TrimSpace(
			message.Notification.NotificationCode,
		),
	}

	normalizedMessage := strings.Join(
		parts,
		" ",
	)

	normalizedMessage = strings.Join(
		strings.Fields(normalizedMessage),
		" ",
	)

	return truncateSMSMessage(
		normalizedMessage,
		maximumLength,
	)
}

func truncateSMSMessage(
	value string,
	maximumLength int,
) string {
	if maximumLength <= 0 {
		return value
	}

	characters := []rune(value)

	if len(characters) <= maximumLength {
		return value
	}

	if maximumLength <= 3 {
		return string(
			characters[:maximumLength],
		)
	}

	return string(
		characters[:maximumLength-3],
	) + "..."
}

func normalizeSMSCountryCode(
	value string,
) (string, error) {
	value = strings.TrimSpace(value)

	value = strings.ReplaceAll(
		value,
		" ",
		"",
	)
	value = strings.ReplaceAll(
		value,
		"-",
		"",
	)

	if strings.HasPrefix(value, "00") {
		value = "+" + strings.TrimPrefix(
			value,
			"00",
		)
	}

	if !strings.HasPrefix(value, "+") {
		value = "+" + value
	}

	digits := strings.TrimPrefix(value, "+")

	if len(digits) < 1 || len(digits) > 3 {
		return "", errors.New(
			"SMS default country code is invalid",
		)
	}

	if !containsOnlySMSDigits(digits) {
		return "", errors.New(
			"SMS default country code must contain only digits",
		)
	}

	return "+" + digits, nil
}

func normalizeSMSPhoneNumber(
	value string,
	defaultCountryCode string,
) (string, error) {
	value = strings.TrimSpace(value)

	replacer := strings.NewReplacer(
		" ", "",
		"-", "",
		"(", "",
		")", "",
		".", "",
	)

	value = replacer.Replace(value)

	if strings.HasPrefix(value, "00") {
		value = "+" + strings.TrimPrefix(
			value,
			"00",
		)
	}

	if !strings.HasPrefix(value, "+") {
		if defaultCountryCode == "" {
			return "", errors.New(
				"SMS phone number must use international E.164 format",
			)
		}

		value = defaultCountryCode + value
	}

	digits := strings.TrimPrefix(value, "+")

	if len(digits) < 8 || len(digits) > 15 {
		return "", errors.New(
			"SMS phone number must contain between 8 and 15 digits",
		)
	}

	if !containsOnlySMSDigits(digits) {
		return "", errors.New(
			"SMS phone number contains invalid characters",
		)
	}

	if strings.HasPrefix(digits, "0") {
		return "", errors.New(
			"SMS phone number country code cannot begin with zero",
		)
	}

	return "+" + digits, nil
}

func containsOnlySMSDigits(
	value string,
) bool {
	if value == "" {
		return false
	}

	for _, character := range value {
		if character < '0' ||
			character > '9' {
			return false
		}
	}

	return true
}

func readSMSProviderResponse(
	reader io.Reader,
	maximumSize int64,
) ([]byte, bool, error) {
	if maximumSize <= 0 {
		maximumSize = defaultSMSResponseSize
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

func buildSMSProviderResponse(
	statusCode int,
	status string,
	responseBody []byte,
	truncated bool,
) (json.RawMessage, bool, error) {
	var gatewayResponse any
	delivered := false

	if len(bytes.TrimSpace(responseBody)) > 0 {
		if json.Valid(responseBody) {
			if err := json.Unmarshal(
				responseBody,
				&gatewayResponse,
			); err != nil {
				return nil, false, err
			}

			delivered = smsGatewayResponseDelivered(
				gatewayResponse,
			)
		} else {
			gatewayResponse = strings.TrimSpace(
				string(responseBody),
			)
		}
	}

	encodedResponse, err := json.Marshal(
		map[string]any{
			"http_status_code":   statusCode,
			"http_status":        status,
			"gateway_response":   gatewayResponse,
			"response_truncated": truncated,
			"accepted_at":        time.Now().UTC(),
		},
	)
	if err != nil {
		return nil, false, err
	}

	return encodedResponse, delivered, nil
}

func smsGatewayResponseDelivered(
	response any,
) bool {
	responseObject, ok := response.(map[string]any)
	if !ok {
		return false
	}

	if deliveredValue, exists :=
		responseObject["delivered"].(bool); exists {
		return deliveredValue
	}

	for _, key := range []string{
		"status",
		"delivery_status",
		"deliveryStatus",
	} {
		statusValue, exists :=
			responseObject[key].(string)
		if !exists {
			continue
		}

		switch strings.ToUpper(
			strings.TrimSpace(statusValue),
		) {
		case "DELIVERED",
			"SUCCESS",
			"COMPLETED":
			return true
		}
	}

	return false
}

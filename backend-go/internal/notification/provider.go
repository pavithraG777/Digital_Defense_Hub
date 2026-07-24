package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotificationProviderRequired = errors.New(
		"notification provider is required",
	)
	ErrNotificationProviderNameRequired = errors.New(
		"notification provider name is required",
	)
	ErrNotificationProviderNotRegistered = errors.New(
		"notification provider is not registered",
	)
	ErrNotificationProviderChannelMismatch = errors.New(
		"notification provider channel mismatch",
	)
	ErrNotificationDeliveryMessageInvalid = errors.New(
		"notification delivery message is invalid",
	)
	ErrNotificationProviderResultInvalid = errors.New(
		"notification provider result is invalid",
	)
)

type DeliveryMessage struct {
	Notification Notification
	Recipient    Recipient
	Delivery     Delivery
}

type ProviderResult struct {
	ProviderName      string
	ProviderMessageID *string
	ProviderResponse  json.RawMessage
	Delivered         bool
	SentAt            *time.Time
	DeliveredAt       *time.Time
}

type Provider interface {
	Name() string
	Channel() string

	Send(
		ctx context.Context,
		message DeliveryMessage,
	) (*ProviderResult, error)
}

type DeliveryProviderError struct {
	Err         error
	Retryable   bool
	RetryAfter  time.Duration
	NextRetryAt *time.Time
}

func (e *DeliveryProviderError) Error() string {
	if e == nil || e.Err == nil {
		return "notification delivery provider error"
	}

	return e.Err.Error()
}

func (e *DeliveryProviderError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

func NewRetryableDeliveryError(
	err error,
	retryAfter time.Duration,
) error {
	if err == nil {
		err = errors.New(
			"retryable notification delivery failure",
		)
	}

	if retryAfter < 0 {
		retryAfter = 0
	}

	return &DeliveryProviderError{
		Err:        err,
		Retryable:  true,
		RetryAfter: retryAfter,
	}
}

func NewRetryableDeliveryErrorAt(
	err error,
	nextRetryAt time.Time,
) error {
	if err == nil {
		err = errors.New(
			"retryable notification delivery failure",
		)
	}

	normalizedRetryAt := nextRetryAt.UTC()

	return &DeliveryProviderError{
		Err:         err,
		Retryable:   true,
		NextRetryAt: &normalizedRetryAt,
	}
}

func NewPermanentDeliveryError(
	err error,
) error {
	if err == nil {
		err = errors.New(
			"permanent notification delivery failure",
		)
	}

	return &DeliveryProviderError{
		Err:       err,
		Retryable: false,
	}
}

func IsRetryableDeliveryError(
	err error,
) bool {
	var providerError *DeliveryProviderError

	if !errors.As(err, &providerError) {
		return false
	}

	return providerError.Retryable
}

func ResolveDeliveryRetryTime(
	err error,
	failedAt time.Time,
	defaultDelay time.Duration,
) *time.Time {
	var providerError *DeliveryProviderError

	if !errors.As(err, &providerError) ||
		!providerError.Retryable {
		return nil
	}

	failedAt = failedAt.UTC()

	if providerError.NextRetryAt != nil {
		retryAt := providerError.NextRetryAt.UTC()

		if retryAt.After(failedAt) {
			return &retryAt
		}
	}

	retryDelay := providerError.RetryAfter

	if retryDelay <= 0 {
		retryDelay = defaultDelay
	}

	if retryDelay <= 0 {
		retryDelay = time.Minute
	}

	retryAt := failedAt.Add(retryDelay)

	return &retryAt
}

type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

func NewProviderRegistry(
	providers ...Provider,
) (*ProviderRegistry, error) {
	registry := &ProviderRegistry{
		providers: make(
			map[string]Provider,
		),
	}

	for _, provider := range providers {
		if err := registry.Register(provider); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

func (r *ProviderRegistry) Register(
	provider Provider,
) error {
	if r == nil {
		return errors.New(
			"notification provider registry is unavailable",
		)
	}

	if provider == nil {
		return ErrNotificationProviderRequired
	}

	providerName := strings.TrimSpace(
		provider.Name(),
	)

	channel := strings.ToUpper(
		strings.TrimSpace(
			provider.Channel(),
		),
	)

	if providerName == "" {
		return ErrNotificationProviderNameRequired
	}

	if !isServiceNotificationChannelSupported(
		channel,
	) {
		return fmt.Errorf(
			"%w: %s",
			ErrInvalidNotificationChannel,
			channel,
		)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.providers == nil {
		r.providers = make(
			map[string]Provider,
		)
	}

	r.providers[channel] = provider

	return nil
}

func (r *ProviderRegistry) Get(
	channel string,
) (Provider, error) {
	if r == nil {
		return nil, errors.New(
			"notification provider registry is unavailable",
		)
	}

	channel = strings.ToUpper(
		strings.TrimSpace(channel),
	)

	if !isServiceNotificationChannelSupported(
		channel,
	) {
		return nil, fmt.Errorf(
			"%w: %s",
			ErrInvalidNotificationChannel,
			channel,
		)
	}

	r.mu.RLock()
	provider, exists := r.providers[channel]
	r.mu.RUnlock()

	if !exists || provider == nil {
		return nil, fmt.Errorf(
			"%w: %s",
			ErrNotificationProviderNotRegistered,
			channel,
		)
	}

	providerChannel := strings.ToUpper(
		strings.TrimSpace(
			provider.Channel(),
		),
	)

	if providerChannel != channel {
		return nil, fmt.Errorf(
			"%w: requested %s but provider returned %s",
			ErrNotificationProviderChannelMismatch,
			channel,
			providerChannel,
		)
	}

	return provider, nil
}

func (r *ProviderRegistry) Has(
	channel string,
) bool {
	if r == nil {
		return false
	}

	channel = strings.ToUpper(
		strings.TrimSpace(channel),
	)

	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, exists := r.providers[channel]

	return exists && provider != nil
}

func (r *ProviderRegistry) Channels() []string {
	if r == nil {
		return []string{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	channels := make(
		[]string,
		0,
		len(r.providers),
	)

	for channel, provider := range r.providers {
		if provider == nil {
			continue
		}

		channels = append(
			channels,
			channel,
		)
	}

	sort.Strings(channels)

	return channels
}

func ValidateDeliveryMessage(
	message DeliveryMessage,
) error {
	if message.Notification.ID == uuid.Nil {
		return fmt.Errorf(
			"%w: notification ID is required",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	if message.Recipient.ID == uuid.Nil {
		return fmt.Errorf(
			"%w: recipient ID is required",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	if message.Delivery.ID == uuid.Nil {
		return fmt.Errorf(
			"%w: delivery ID is required",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	if message.Delivery.NotificationID !=
		message.Notification.ID {
		return fmt.Errorf(
			"%w: notification reference mismatch",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	if message.Delivery.RecipientID !=
		message.Recipient.ID {
		return fmt.Errorf(
			"%w: recipient reference mismatch",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	if message.Notification.OrganizationID !=
		message.Recipient.OrganizationID ||
		message.Notification.OrganizationID !=
			message.Delivery.OrganizationID {
		return fmt.Errorf(
			"%w: organization reference mismatch",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	channel := strings.ToUpper(
		strings.TrimSpace(
			message.Delivery.Channel,
		),
	)

	if !isServiceNotificationChannelSupported(
		channel,
	) {
		return fmt.Errorf(
			"%w: unsupported delivery channel",
			ErrNotificationDeliveryMessageInvalid,
		)
	}

	return nil
}

func NormalizeProviderResult(
	provider Provider,
	result *ProviderResult,
	processedAt time.Time,
) (*ProviderResult, error) {
	if provider == nil {
		return nil, ErrNotificationProviderRequired
	}

	if result == nil {
		return nil, ErrNotificationProviderResultInvalid
	}

	providerName := strings.TrimSpace(
		result.ProviderName,
	)

	if providerName == "" {
		providerName = strings.TrimSpace(
			provider.Name(),
		)
	}

	if providerName == "" {
		return nil, ErrNotificationProviderNameRequired
	}

	providerMessageID :=
		normalizeNotificationDeliveryString(
			result.ProviderMessageID,
		)

	providerResponse := bytes.TrimSpace(
		result.ProviderResponse,
	)

	if len(providerResponse) == 0 {
		providerResponse = []byte(`{}`)
	}

	if !json.Valid(providerResponse) {
		return nil, ErrNotificationProviderResultInvalid
	}

	if processedAt.IsZero() {
		processedAt = time.Now().UTC()
	} else {
		processedAt = processedAt.UTC()
	}

	sentAt := normalizeProviderResultTime(
		result.SentAt,
	)

	deliveredAt := normalizeProviderResultTime(
		result.DeliveredAt,
	)

	if sentAt == nil {
		normalizedSentAt := processedAt
		sentAt = &normalizedSentAt
	}

	if result.Delivered &&
		deliveredAt == nil {
		normalizedDeliveredAt := processedAt
		deliveredAt = &normalizedDeliveredAt
	}

	copiedResponse := append(
		json.RawMessage(nil),
		providerResponse...,
	)

	return &ProviderResult{
		ProviderName:      providerName,
		ProviderMessageID: providerMessageID,
		ProviderResponse:  copiedResponse,
		Delivered:         result.Delivered,
		SentAt:            sentAt,
		DeliveredAt:       deliveredAt,
	}, nil
}

func normalizeProviderResultTime(
	value *time.Time,
) *time.Time {
	if value == nil {
		return nil
	}

	normalizedValue := value.UTC()

	return &normalizedValue
}

package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const inAppProviderName = "DDH_IN_APP"

type InAppProvider struct{}

func NewInAppProvider() *InAppProvider {
	return &InAppProvider{}
}

func (p *InAppProvider) Name() string {
	return inAppProviderName
}

func (p *InAppProvider) Channel() string {
	return "IN_APP"
}

func (p *InAppProvider) Send(
	ctx context.Context,
	message DeliveryMessage,
) (*ProviderResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, NewRetryableDeliveryError(
			err,
			time.Minute,
		)
	}

	if err := ValidateDeliveryMessage(
		message,
	); err != nil {
		return nil, NewPermanentDeliveryError(
			err,
		)
	}

	channel := strings.ToUpper(
		strings.TrimSpace(
			message.Delivery.Channel,
		),
	)

	if channel != p.Channel() {
		return nil, NewPermanentDeliveryError(
			fmt.Errorf(
				"%w: expected %s but received %s",
				ErrNotificationProviderChannelMismatch,
				p.Channel(),
				channel,
			),
		)
	}

	if message.Recipient.RecipientType != "USER" {
		return nil, NewPermanentDeliveryError(
			errors.New(
				"in-app notification requires a user recipient",
			),
		)
	}

	if message.Recipient.UserID == nil ||
		*message.Recipient.UserID == uuid.Nil {
		return nil, NewPermanentDeliveryError(
			errors.New(
				"in-app notification recipient user ID is required",
			),
		)
	}

	processedAt := time.Now().UTC()

	providerMessageID :=
		message.Delivery.ID.String()

	providerResponse, err := json.Marshal(
		map[string]any{
			"provider":          p.Name(),
			"channel":           p.Channel(),
			"stored":            true,
			"notification_id":   message.Notification.ID.String(),
			"notification_code": message.Notification.NotificationCode,
			"recipient_id":      message.Recipient.ID.String(),
			"recipient_user_id": message.Recipient.UserID.String(),
			"processed_at":      processedAt.Format(time.RFC3339Nano),
		},
	)
	if err != nil {
		return nil, NewPermanentDeliveryError(
			fmt.Errorf(
				"marshal in-app provider response: %w",
				err,
			),
		)
	}

	return &ProviderResult{
		ProviderName:      p.Name(),
		ProviderMessageID: &providerMessageID,
		ProviderResponse:  providerResponse,
		Delivered:         true,
		SentAt:            &processedAt,
		DeliveredAt:       &processedAt,
	}, nil
}

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

const (
	defaultNotificationRetryDelay = time.Minute
	maximumNotificationRetryDelay = 30 * time.Minute
)

type Dispatcher struct {
	repository *Repository
	providers  *ProviderRegistry
}

func NewDispatcher(
	repository *Repository,
	providers *ProviderRegistry,
) (*Dispatcher, error) {
	if repository == nil {
		return nil, errors.New(
			"notification repository is required",
		)
	}

	if providers == nil {
		return nil, errors.New(
			"notification provider registry is required",
		)
	}

	return &Dispatcher{
		repository: repository,
		providers:  providers,
	}, nil
}

func (d *Dispatcher) Dispatch(
	ctx context.Context,
	delivery *Delivery,
) (*Delivery, error) {
	if d == nil ||
		d.repository == nil ||
		d.providers == nil {
		return nil, errors.New(
			"notification dispatcher is unavailable",
		)
	}

	if delivery == nil {
		return nil, errors.New(
			"notification delivery is required",
		)
	}

	if delivery.ID == uuid.Nil ||
		delivery.OrganizationID == uuid.Nil ||
		delivery.NotificationID == uuid.Nil ||
		delivery.RecipientID == uuid.Nil {
		return nil, ErrNotificationDeliveryMessageInvalid
	}

	if delivery.DeliveryStatus != "PROCESSING" {
		return nil, fmt.Errorf(
			"%w: expected PROCESSING but received %s",
			ErrNotificationDeliveryStateConflict,
			delivery.DeliveryStatus,
		)
	}

	notificationRecord, err :=
		d.repository.FindByID(
			ctx,
			delivery.OrganizationID,
			delivery.NotificationID,
		)
	if err != nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewPermanentDeliveryError(err),
			nil,
		)
	}

	recipients, err :=
		d.repository.ListRecipients(
			ctx,
			delivery.OrganizationID,
			delivery.NotificationID,
		)
	if err != nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewRetryableDeliveryError(
				err,
				defaultNotificationRetryDelay,
			),
			nil,
		)
	}

	recipient := findNotificationDeliveryRecipient(
		recipients,
		delivery.RecipientID,
	)
	if recipient == nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewPermanentDeliveryError(
				ErrNotificationRecipientNotFound,
			),
			nil,
		)
	}

	message := DeliveryMessage{
		Notification: *notificationRecord,
		Recipient:    *recipient,
		Delivery:     *delivery,
	}

	if err = ValidateDeliveryMessage(
		message,
	); err != nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewPermanentDeliveryError(err),
			nil,
		)
	}

	provider, err := d.providers.Get(
		delivery.Channel,
	)
	if err != nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewRetryableDeliveryError(
				err,
				5*time.Minute,
			),
			nil,
		)
	}

	result, sendErr := provider.Send(
		ctx,
		message,
	)
	if sendErr != nil {
		normalizedError :=
			normalizeNotificationDispatchError(
				sendErr,
				delivery.AttemptCount,
			)

		return d.handleDeliveryFailure(
			ctx,
			delivery,
			normalizedError,
			providerResultResponse(result),
		)
	}

	processedAt := time.Now().UTC()

	normalizedResult, err :=
		NormalizeProviderResult(
			provider,
			result,
			processedAt,
		)
	if err != nil {
		return d.handleDeliveryFailure(
			ctx,
			delivery,
			NewPermanentDeliveryError(err),
			providerResultResponse(result),
		)
	}

	sentAt := processedAt

	if normalizedResult.SentAt != nil {
		sentAt = normalizedResult.SentAt.UTC()
	}

	providerName :=
		normalizedResult.ProviderName

	sentDelivery, err :=
		d.repository.MarkDeliverySent(
			ctx,
			MarkNotificationDeliverySentInput{
				OrganizationID: delivery.OrganizationID,
				DeliveryID:     delivery.ID,
				ProviderName:   &providerName,
				ProviderMessageID: normalizedResult.
					ProviderMessageID,
				ProviderResponse: normalizedResult.
					ProviderResponse,
				SentAt: sentAt,
			},
		)
	if err != nil {
		return nil, err
	}

	finalDelivery := sentDelivery

	if normalizedResult.Delivered {
		deliveredAt := processedAt

		if normalizedResult.DeliveredAt != nil {
			deliveredAt =
				normalizedResult.DeliveredAt.UTC()
		}

		finalDelivery, err =
			d.repository.MarkDeliveryDelivered(
				ctx,
				MarkNotificationDeliveryDeliveredInput{
					OrganizationID: delivery.OrganizationID,
					DeliveryID:     delivery.ID,
					ProviderResponse: normalizedResult.
						ProviderResponse,
					DeliveredAt: deliveredAt,
				},
			)
		if err != nil {
			return nil, err
		}
	}

	_, err = d.repository.RefreshNotificationDeliveryStatus(
		ctx,
		delivery.OrganizationID,
		delivery.NotificationID,
		processedAt,
	)
	if err != nil {
		return finalDelivery, fmt.Errorf(
			"refresh notification status after delivery: %w",
			err,
		)
	}

	return finalDelivery, nil
}

func (d *Dispatcher) handleDeliveryFailure(
	ctx context.Context,
	delivery *Delivery,
	deliveryError error,
	providerResponse json.RawMessage,
) (*Delivery, error) {
	if deliveryError == nil {
		deliveryError = errors.New(
			"notification delivery failed",
		)
	}

	failedAt := time.Now().UTC()

	defaultRetryDelay :=
		calculateNotificationRetryDelay(
			delivery.AttemptCount,
		)

	retryAt := ResolveDeliveryRetryTime(
		deliveryError,
		failedAt,
		defaultRetryDelay,
	)

	lastError := normalizeNotificationDeliveryError(
		deliveryError,
	)

	failedDelivery, persistErr :=
		d.repository.MarkDeliveryFailed(
			ctx,
			MarkNotificationDeliveryFailedInput{
				OrganizationID:   delivery.OrganizationID,
				DeliveryID:       delivery.ID,
				LastError:        lastError,
				ProviderResponse: providerResponse,
				RetryAt:          retryAt,
				FailedAt:         failedAt,
			},
		)
	if persistErr != nil {
		return nil, fmt.Errorf(
			"persist notification delivery failure: %w; original delivery error: %v",
			persistErr,
			deliveryError,
		)
	}

	_, refreshErr :=
		d.repository.RefreshNotificationDeliveryStatus(
			ctx,
			delivery.OrganizationID,
			delivery.NotificationID,
			failedAt,
		)
	if refreshErr != nil {
		return failedDelivery, fmt.Errorf(
			"notification delivery failed: %v; refresh notification status: %w",
			deliveryError,
			refreshErr,
		)
	}

	return failedDelivery, deliveryError
}

func findNotificationDeliveryRecipient(
	recipients []Recipient,
	recipientID uuid.UUID,
) *Recipient {
	for index := range recipients {
		if recipients[index].ID ==
			recipientID {
			return &recipients[index]
		}
	}

	return nil
}

func normalizeNotificationDispatchError(
	err error,
	attemptCount int,
) error {
	if err == nil {
		return NewRetryableDeliveryError(
			errors.New(
				"notification provider returned an unknown error",
			),
			calculateNotificationRetryDelay(
				attemptCount,
			),
		)
	}

	var providerError *DeliveryProviderError

	if errors.As(err, &providerError) {
		return err
	}

	if errors.Is(err, context.Canceled) {
		return NewRetryableDeliveryError(
			err,
			defaultNotificationRetryDelay,
		)
	}

	if errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		return NewRetryableDeliveryError(
			err,
			calculateNotificationRetryDelay(
				attemptCount,
			),
		)
	}

	return NewRetryableDeliveryError(
		err,
		calculateNotificationRetryDelay(
			attemptCount,
		),
	)
}

func calculateNotificationRetryDelay(
	attemptCount int,
) time.Duration {
	if attemptCount <= 0 {
		attemptCount = 1
	}

	retryDelay :=
		defaultNotificationRetryDelay

	for attempt := 1; attempt < attemptCount; attempt++ {
		retryDelay *= 2

		if retryDelay >=
			maximumNotificationRetryDelay {
			return maximumNotificationRetryDelay
		}
	}

	return retryDelay
}

func normalizeNotificationDeliveryError(
	err error,
) string {
	if err == nil {
		return "notification delivery failed"
	}

	errorMessage := strings.TrimSpace(
		err.Error(),
	)

	if errorMessage == "" {
		errorMessage =
			"notification delivery failed"
	}

	const maximumErrorLength = 4000

	if len(errorMessage) >
		maximumErrorLength {
		errorMessage =
			errorMessage[:maximumErrorLength]
	}

	return errorMessage
}

func providerResultResponse(
	result *ProviderResult,
) json.RawMessage {
	if result == nil ||
		len(result.ProviderResponse) == 0 {
		return json.RawMessage(`{}`)
	}

	if !json.Valid(
		result.ProviderResponse,
	) {
		return json.RawMessage(`{}`)
	}

	return append(
		json.RawMessage(nil),
		result.ProviderResponse...,
	)
}

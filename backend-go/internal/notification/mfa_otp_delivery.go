package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MFAOTPDelivery sends a single email OTP. SMS is deliberately not required
// for development and small deployments.
// It deliberately has no dependency on the auth package.
type MFAOTPDelivery struct{ providers *ProviderRegistry }

func NewMFAOTPDelivery(providers *ProviderRegistry) (*MFAOTPDelivery, error) {
	if providers == nil {
		return nil, errors.New("notification provider registry is required")
	}
	return &MFAOTPDelivery{providers: providers}, nil
}

func (d *MFAOTPDelivery) DeliverMFAOTP(ctx context.Context, emailAddress, emailCode string) error {
	if d == nil || d.providers == nil {
		return errors.New("MFA delivery is unavailable")
	}
	if err := d.send(ctx, "EMAIL", emailAddress, "Your Digital Defense Hub email verification code is "+emailCode+". It expires in 10 minutes."); err != nil {
		return fmt.Errorf("email OTP: %w", err)
	}
	return nil
}

func (d *MFAOTPDelivery) send(ctx context.Context, channel, address, body string) error {
	provider, err := d.providers.Get(channel)
	if err != nil {
		return err
	}
	now, id := time.Now().UTC(), uuid.New()
	n := Notification{ID: id, OrganizationID: uuid.New(), NotificationCode: "MFA-OTP", Title: "MFA verification code", Message: body, CreatedAt: now, UpdatedAt: now}
	r := Recipient{ID: uuid.New(), NotificationID: id, OrganizationID: n.OrganizationID, RecipientType: "EXTERNAL", CreatedAt: now, UpdatedAt: now}
	if channel == "EMAIL" {
		r.EmailAddress = &address
	} else {
		r.PhoneNumber = &address
	}
	delivery := Delivery{ID: uuid.New(), NotificationID: id, RecipientID: r.ID, OrganizationID: n.OrganizationID, Channel: channel, DeliveryStatus: "PROCESSING", MaximumAttempts: 1, ScheduledAt: now, CreatedAt: now, UpdatedAt: now}
	_, err = provider.Send(ctx, DeliveryMessage{Notification: n, Recipient: r, Delivery: delivery})
	return err
}

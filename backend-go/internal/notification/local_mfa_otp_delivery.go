package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LocalMFAOTPDelivery is for explicitly enabled development-only testing.
// It writes OTPs to a local, git-ignored outbox instead of transmitting them.
type LocalMFAOTPDelivery struct{ outboxPath string }

func NewLocalMFAOTPDelivery(outboxPath string) (*LocalMFAOTPDelivery, error) {
	absolutePath, err := filepath.Abs(filepath.Clean(strings.TrimSpace(outboxPath)))
	if err != nil {
		return nil, fmt.Errorf("resolve MFA local outbox: %w", err)
	}
	if absolutePath == filepath.VolumeName(absolutePath)+string(os.PathSeparator) {
		return nil, errors.New("MFA local outbox cannot be a filesystem root")
	}
	return &LocalMFAOTPDelivery{outboxPath: absolutePath}, nil
}

func (d *LocalMFAOTPDelivery) DeliverMFAOTP(ctx context.Context, email, emailCode string) error {
	if d == nil || d.outboxPath == "" {
		return errors.New("local MFA delivery is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(d.outboxPath, 0700); err != nil {
		return fmt.Errorf("create MFA local outbox: %w", err)
	}
	payload, err := json.MarshalIndent(struct {
		Email     string    `json:"email"`
		EmailCode string    `json:"email_code"`
		ExpiresAt time.Time `json:"expires_at"`
	}{email, emailCode, time.Now().UTC().Add(10 * time.Minute)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.outboxPath, "mfa-"+uuid.NewString()+".json"), payload, 0600)
}

package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func (r *Repository) GetMFAUserPhone(ctx context.Context, userID uuid.UUID) (string, error) {
	var phone *string
	err := r.db.QueryRow(ctx, `SELECT official_phone FROM user_profiles WHERE user_id = $1`, userID).Scan(&phone)
	if err != nil || phone == nil {
		return "", err
	}
	return strings.TrimSpace(*phone), nil
}

func (r *Repository) CreateMFAChallenge(ctx context.Context, userID, organizationID uuid.UUID, emailHash, smsHash string, expiresAt time.Time) (uuid.UUID, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'CANCELLED' WHERE user_id = $1 AND organization_id = $2 AND status = 'PENDING'`, userID, organizationID); err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO authentication_mfa_challenges (id, user_id, organization_id, email_code_hash, sms_code_hash, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, id, userID, organizationID, emailHash, smsHash, expiresAt.UTC())
	if err != nil {
		return uuid.Nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (r *Repository) CancelMFAChallenge(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'CANCELLED' WHERE id = $1 AND status = 'PENDING'`, id)
	return err
}

func (r *Repository) FindActiveMFAChallenge(ctx context.Context, id uuid.UUID) (*MFAChallenge, error) {
	c := &MFAChallenge{ID: id}
	err := r.db.QueryRow(ctx, `SELECT user_id, organization_id, email_code_hash, sms_code_hash, status, attempts, maximum_attempts, expires_at FROM authentication_mfa_challenges WHERE id = $1`, id).Scan(&c.UserID, &c.OrganizationID, &c.EmailCodeHash, &c.SMSCodeHash, &c.Status, &c.Attempts, &c.MaximumAttempts, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMFAChallengeInvalid
	}
	if err != nil {
		return nil, err
	}
	if c.Status != "PENDING" || c.Attempts >= c.MaximumAttempts || !time.Now().UTC().Before(c.ExpiresAt) {
		if c.Status == "PENDING" && !time.Now().UTC().Before(c.ExpiresAt) {
			_, _ = r.db.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'EXPIRED' WHERE id = $1 AND status = 'PENDING'`, id)
		}
		return nil, ErrMFAChallengeInvalid
	}
	return c, nil
}

func (r *Repository) RecordMFAChallengeFailure(ctx context.Context, id uuid.UUID) error {
	var attempts, maximumAttempts int
	err := r.db.QueryRow(ctx, `UPDATE authentication_mfa_challenges SET attempts = attempts + 1, status = CASE WHEN attempts + 1 >= maximum_attempts THEN 'LOCKED' ELSE status END WHERE id = $1 AND status = 'PENDING' AND expires_at > CURRENT_TIMESTAMP RETURNING attempts, maximum_attempts`, id).Scan(&attempts, &maximumAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrMFAChallengeInvalid
	}
	if err != nil {
		return err
	}
	if attempts >= maximumAttempts {
		return ErrMFAChallengeLocked
	}
	return ErrMFAChallengeInvalid
}

func (r *Repository) ConsumeMFAChallenge(ctx context.Context, id, userID, organizationID uuid.UUID) (*MFAChallenge, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c := &MFAChallenge{ID: id}
	err = tx.QueryRow(ctx, `SELECT user_id, organization_id, email_code_hash, sms_code_hash, status, attempts, maximum_attempts, expires_at FROM authentication_mfa_challenges WHERE id = $1 FOR UPDATE`, id).Scan(&c.UserID, &c.OrganizationID, &c.EmailCodeHash, &c.SMSCodeHash, &c.Status, &c.Attempts, &c.MaximumAttempts, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMFAChallengeInvalid
	}
	if err != nil {
		return nil, err
	}
	if c.UserID != userID || c.OrganizationID != organizationID || c.Status != "PENDING" || c.Attempts >= c.MaximumAttempts || !time.Now().UTC().Before(c.ExpiresAt) {
		return nil, ErrMFAChallengeInvalid
	}
	if _, err = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'VERIFIED', consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'PENDING'`, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (r *Repository) ConsumeRecoveryCodeAndMFAChallenge(ctx context.Context, id, userID, organizationID uuid.UUID, recoveryCodeHash string) (*MFAChallenge, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c := &MFAChallenge{ID: id}
	err = tx.QueryRow(ctx, `SELECT user_id, organization_id, email_code_hash, sms_code_hash, status, attempts, maximum_attempts, expires_at FROM authentication_mfa_challenges WHERE id = $1 FOR UPDATE`, id).Scan(&c.UserID, &c.OrganizationID, &c.EmailCodeHash, &c.SMSCodeHash, &c.Status, &c.Attempts, &c.MaximumAttempts, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMFAChallengeInvalid
	}
	if err != nil {
		return nil, err
	}
	if c.UserID != userID || c.OrganizationID != organizationID || c.Status != "PENDING" || c.Attempts >= c.MaximumAttempts || !time.Now().UTC().Before(c.ExpiresAt) {
		return nil, ErrMFAChallengeInvalid
	}
	result, err := tx.Exec(ctx, `UPDATE users SET mfa_recovery_code_hashes = array_remove(mfa_recovery_code_hashes, $3), updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL AND $3 = ANY(mfa_recovery_code_hashes)`, userID, organizationID, recoveryCodeHash)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() != 1 {
		return nil, ErrMFAChallengeInvalid
	}
	if _, err = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'VERIFIED', consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'PENDING'`, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (r *Repository) VerifyAndConsumeMFAChallenge(ctx context.Context, id uuid.UUID, emailCode, smsCode string) (*MFAChallenge, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c := &MFAChallenge{ID: id}
	err = tx.QueryRow(ctx, `SELECT user_id, organization_id, email_code_hash, sms_code_hash, status, attempts, maximum_attempts, expires_at FROM authentication_mfa_challenges WHERE id = $1 FOR UPDATE`, id).Scan(&c.UserID, &c.OrganizationID, &c.EmailCodeHash, &c.SMSCodeHash, &c.Status, &c.Attempts, &c.MaximumAttempts, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMFAChallengeInvalid
	}
	if err != nil {
		return nil, err
	}
	if c.Status != "PENDING" || !time.Now().UTC().Before(c.ExpiresAt) {
		if c.Status == "PENDING" {
			_, _ = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'EXPIRED' WHERE id = $1`, id)
			_ = tx.Commit(ctx)
		}
		return nil, ErrMFAChallengeInvalid
	}
	emailOK := bcrypt.CompareHashAndPassword([]byte(c.EmailCodeHash), []byte(emailCode)) == nil
	smsOK := bcrypt.CompareHashAndPassword([]byte(c.SMSCodeHash), []byte(smsCode)) == nil
	if !emailOK || !smsOK {
		c.Attempts++
		status := "PENDING"
		if c.Attempts >= c.MaximumAttempts {
			status = "LOCKED"
		}
		_, err = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET attempts = $2, status = $3 WHERE id = $1`, id, c.Attempts, status)
		if err != nil {
			return nil, err
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		if status == "LOCKED" {
			return nil, ErrMFAChallengeLocked
		}
		return nil, ErrMFAChallengeInvalid
	}
	_, err = tx.Exec(ctx, `UPDATE authentication_mfa_challenges SET status = 'VERIFIED', consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'PENDING'`, id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

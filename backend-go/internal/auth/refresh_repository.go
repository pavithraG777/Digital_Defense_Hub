package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenInactive = errors.New("refresh token is not active")
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
)

// CreateRefreshToken saves the refresh token in the database.
//
// The original token is not stored. Only its SHA-256 hash is stored
// using the existing hashSessionToken function from repository.go.
func (r *Repository) CreateRefreshToken(
	ctx context.Context,
	tokenID uuid.UUID,
	userID uuid.UUID,
	sessionID uuid.UUID,
	rawToken string,
	expiresAt time.Time,
) error {
	if tokenID == uuid.Nil {
		return fmt.Errorf("refresh token ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if rawToken == "" {
		return fmt.Errorf("refresh token is required")
	}

	if expiresAt.IsZero() {
		return fmt.Errorf("refresh token expiry time is required")
	}

	if !expiresAt.After(time.Now()) {
		return fmt.Errorf("refresh token expiry time must be in the future")
	}

	const query = `
		INSERT INTO refresh_tokens (
			id,
			user_id,
			session_id,
			token_hash,
			issued_at,
			expires_at,
			status,
			created_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			CURRENT_TIMESTAMP,
			$5,
			'ACTIVE',
			CURRENT_TIMESTAMP
		);
	`

	_, err := r.db.Exec(
		ctx,
		query,
		tokenID,
		userID,
		sessionID,
		hashSessionToken(rawToken),
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create refresh token: %w",
			err,
		)
	}

	return nil
}

// FindRefreshToken finds a refresh token using the hash of the raw token.
func (r *Repository) FindRefreshToken(
	ctx context.Context,
	rawToken string,
) (*RefreshToken, error) {
	if rawToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	const query = `
		SELECT
			id,
			user_id,
			session_id,
			token_hash,
			issued_at,
			expires_at,
			last_used_at,
			revoked_at,
			replaced_by_token_id,
			revocation_reason,
			status,
			created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		LIMIT 1;
	`

	var token RefreshToken

	err := r.db.QueryRow(
		ctx,
		query,
		hashSessionToken(rawToken),
	).Scan(
		&token.ID,
		&token.UserID,
		&token.SessionID,
		&token.TokenHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.LastUsedAt,
		&token.RevokedAt,
		&token.ReplacedByTokenID,
		&token.RevocationReason,
		&token.Status,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf(
			"failed to find refresh token: %w",
			err,
		)
	}

	return &token, nil
}

// ValidateRefreshToken verifies whether a refresh token can still be used.
func (r *Repository) ValidateRefreshToken(
	ctx context.Context,
	rawToken string,
) (*RefreshToken, error) {
	token, err := r.FindRefreshToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	if token.Status != "ACTIVE" {
		return nil, ErrRefreshTokenInactive
	}

	if token.RevokedAt != nil {
		return nil, ErrRefreshTokenInactive
	}

	if time.Now().After(token.ExpiresAt) {
		if err := r.MarkRefreshTokenExpired(
			ctx,
			token.ID,
		); err != nil {
			return nil, fmt.Errorf(
				"failed to mark refresh token as expired: %w",
				err,
			)
		}

		return nil, ErrRefreshTokenExpired
	}

	return token, nil
}

// MarkRefreshTokenUsed records the latest successful use of a refresh token.
func (r *Repository) MarkRefreshTokenUsed(
	ctx context.Context,
	tokenID uuid.UUID,
) error {
	if tokenID == uuid.Nil {
		return fmt.Errorf("refresh token ID is required")
	}

	const query = `
		UPDATE refresh_tokens
		SET
			last_used_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update refresh token usage: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrRefreshTokenInactive
	}

	return nil
}

// MarkRefreshTokenExpired changes an active expired token to EXPIRED.
func (r *Repository) MarkRefreshTokenExpired(
	ctx context.Context,
	tokenID uuid.UUID,
) error {
	if tokenID == uuid.Nil {
		return fmt.Errorf("refresh token ID is required")
	}

	const query = `
		UPDATE refresh_tokens
		SET
			status = 'EXPIRED',
			revoked_at = COALESCE(
				revoked_at,
				CURRENT_TIMESTAMP
			),
			revocation_reason = COALESCE(
				revocation_reason,
				'TOKEN_EXPIRED'
			)
		WHERE
			id = $1
			AND status = 'ACTIVE';
	`

	_, err := r.db.Exec(
		ctx,
		query,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to expire refresh token: %w",
			err,
		)
	}

	return nil
}

// RotateRefreshToken revokes the old token and creates a new token.
//
// Both operations are performed inside a single database transaction.
func (r *Repository) RotateRefreshToken(
	ctx context.Context,
	oldTokenID uuid.UUID,
	newTokenID uuid.UUID,
	userID uuid.UUID,
	sessionID uuid.UUID,
	newRawToken string,
	newExpiresAt time.Time,
) error {
	if oldTokenID == uuid.Nil {
		return fmt.Errorf("old refresh token ID is required")
	}

	if newTokenID == uuid.Nil {
		return fmt.Errorf("new refresh token ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if newRawToken == "" {
		return fmt.Errorf("new refresh token is required")
	}

	if newExpiresAt.IsZero() {
		return fmt.Errorf("new refresh token expiry time is required")
	}

	if !newExpiresAt.After(time.Now()) {
		return fmt.Errorf(
			"new refresh token expiry time must be in the future",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"failed to begin refresh token rotation: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const validateOldTokenQuery = `
		SELECT id
		FROM refresh_tokens
		WHERE
			id = $1
			AND user_id = $2
			AND session_id = $3
			AND status = 'ACTIVE'
			AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP
		FOR UPDATE;
	`

	var validatedTokenID uuid.UUID

	err = tx.QueryRow(
		ctx,
		validateOldTokenQuery,
		oldTokenID,
		userID,
		sessionID,
	).Scan(&validatedTokenID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRefreshTokenInactive
		}

		return fmt.Errorf(
			"failed to validate old refresh token: %w",
			err,
		)
	}

	const createNewTokenQuery = `
		INSERT INTO refresh_tokens (
			id,
			user_id,
			session_id,
			token_hash,
			issued_at,
			expires_at,
			status,
			created_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			CURRENT_TIMESTAMP,
			$5,
			'ACTIVE',
			CURRENT_TIMESTAMP
		);
	`

	_, err = tx.Exec(
		ctx,
		createNewTokenQuery,
		newTokenID,
		userID,
		sessionID,
		hashSessionToken(newRawToken),
		newExpiresAt,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create rotated refresh token: %w",
			err,
		)
	}

	const revokeOldTokenQuery = `
		UPDATE refresh_tokens
		SET
			status = 'REPLACED',
			last_used_at = CURRENT_TIMESTAMP,
			revoked_at = CURRENT_TIMESTAMP,
			replaced_by_token_id = $2,
			revocation_reason = 'TOKEN_ROTATED'
		WHERE
			id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	commandTag, err := tx.Exec(
		ctx,
		revokeOldTokenQuery,
		oldTokenID,
		newTokenID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke old refresh token: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrRefreshTokenInactive
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"failed to commit refresh token rotation: %w",
			err,
		)
	}

	return nil
}

// RevokeRefreshToken revokes one refresh token.
func (r *Repository) RevokeRefreshToken(
	ctx context.Context,
	tokenID uuid.UUID,
	reason string,
) error {
	if tokenID == uuid.Nil {
		return fmt.Errorf("refresh token ID is required")
	}

	if reason == "" {
		reason = "TOKEN_REVOKED"
	}

	const query = `
		UPDATE refresh_tokens
		SET
			status = 'REVOKED',
			revoked_at = CURRENT_TIMESTAMP,
			revocation_reason = $2
		WHERE
			id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		tokenID,
		reason,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke refresh token: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrRefreshTokenInactive
	}

	return nil
}

// RevokeSessionRefreshTokens revokes every active refresh token
// belonging to one authentication session.
func (r *Repository) RevokeSessionRefreshTokens(
	ctx context.Context,
	sessionID uuid.UUID,
	reason string,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if reason == "" {
		reason = "SESSION_TERMINATED"
	}

	const query = `
		UPDATE refresh_tokens
		SET
			status = 'REVOKED',
			revoked_at = CURRENT_TIMESTAMP,
			revocation_reason = $2
		WHERE
			session_id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	_, err := r.db.Exec(
		ctx,
		query,
		sessionID,
		reason,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke session refresh tokens: %w",
			err,
		)
	}

	return nil
}

// RevokeAllUserRefreshTokens revokes all active refresh tokens
// belonging to a user.
func (r *Repository) RevokeAllUserRefreshTokens(
	ctx context.Context,
	userID uuid.UUID,
	reason string,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if reason == "" {
		reason = "ALL_SESSIONS_TERMINATED"
	}

	const query = `
		UPDATE refresh_tokens
		SET
			status = 'REVOKED',
			revoked_at = CURRENT_TIMESTAMP,
			revocation_reason = $2
		WHERE
			user_id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	_, err := r.db.Exec(
		ctx,
		query,
		userID,
		reason,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke all user refresh tokens: %w",
			err,
		)
	}

	return nil
}

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const passwordResetTokenDuration = 15 * time.Minute

type GeneratedPasswordResetToken struct {
	ID        uuid.UUID
	Token     string
	TokenHash string
	ExpiresAt time.Time
}

// GeneratePasswordResetToken creates a secure random token.
// Only the hashed token should be stored in the database.
func GeneratePasswordResetToken() (
	*GeneratedPasswordResetToken,
	error,
) {
	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf(
			"failed to generate password reset token: %w",
			err,
		)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(
		randomBytes,
	)

	tokenHash := HashPasswordResetToken(
		rawToken,
	)

	return &GeneratedPasswordResetToken{
		ID:        uuid.New(),
		Token:     rawToken,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(
			passwordResetTokenDuration,
		),
	}, nil
}

// HashPasswordResetToken creates a SHA-256 hash of the raw reset token.
func HashPasswordResetToken(
	token string,
) string {
	normalizedToken := strings.TrimSpace(token)

	hash := sha256.Sum256(
		[]byte(normalizedToken),
	)

	return hex.EncodeToString(
		hash[:],
	)
}

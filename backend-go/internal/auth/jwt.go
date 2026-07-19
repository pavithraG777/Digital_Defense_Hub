package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type JWTManager struct {
	secretKey     []byte
	tokenDuration time.Duration
	issuer        string
}

type Claims struct {
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Username       string    `json:"username"`
	Roles          []string  `json:"roles"`
	jwt.RegisteredClaims
}

func NewJWTManager(
	secret string,
	tokenDuration time.Duration,
	issuer string,
) (*JWTManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf(
			"JWT secret must contain at least 32 characters",
		)
	}

	if tokenDuration <= 0 {
		return nil, fmt.Errorf(
			"JWT token duration must be greater than zero",
		)
	}

	return &JWTManager{
		secretKey:     []byte(secret),
		tokenDuration: tokenDuration,
		issuer:        issuer,
	}, nil
}

func (m *JWTManager) GenerateAccessToken(
	user *User,
	roles []string,
) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(m.tokenDuration)

	claims := Claims{
		UserID:         user.ID,
		OrganizationID: user.OrganizationID,
		Username:       user.Username,
		Roles:          roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    m.issuer,
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf(
			"failed to sign access token: %w",
			err,
		)
	}

	return signedToken, expiresAt, nil
}

func (m *JWTManager) ValidateAccessToken(
	tokenString string,
) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf(
					"unexpected signing method: %s",
					token.Method.Alg(),
				)
			}

			return m.secretKey, nil
		},
		jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}

		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (m *JWTManager) TokenDuration() time.Duration {
	return m.tokenDuration
}

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

const (
	totpDefaultDigits      = 6
	totpDefaultPeriod      = 30
	totpDefaultAlgorithm   = "SHA1"
	totpDriftWindow        = 1
	totpSecretLength       = 20
	totpNonceSize          = 12
	totpRecoveryCodeCount  = 10
	totpRecoveryCodeLength = 10
	totpRecoveryCharset    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

func DecodeMFASecretMasterKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}

	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("MFA_MASTER_KEY must be valid Base64: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("MFA_MASTER_KEY must decode to exactly %d bytes", 32)
	}

	return key, nil
}

func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, totpSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func GenerateTOTPProvisioningURI(accountName, issuer, secret string) string {
	accountName = strings.TrimSpace(accountName)
	issuer = strings.TrimSpace(issuer)
	label := url.QueryEscape(fmt.Sprintf("%s:%s", issuer, accountName))
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", totpDefaultAlgorithm)
	params.Set("digits", fmt.Sprintf("%d", totpDefaultDigits))
	params.Set("period", fmt.Sprintf("%d", totpDefaultPeriod))

	return fmt.Sprintf("otpauth://totp/%s?%s", label, params.Encode())
}

func EncryptTOTPSecret(masterKey []byte, secret string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("MFA master key must be exactly 32 bytes")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MFA encryption cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MFA encryption GCM: %w", err)
	}

	nonce := make([]byte, totpNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate MFA encryption nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return ciphertext, nil
}

func DecryptTOTPSecret(masterKey []byte, data []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("MFA master key must be exactly 32 bytes")
	}

	if len(data) < totpNonceSize {
		return "", fmt.Errorf("invalid MFA secret payload")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize MFA decryption cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to initialize MFA decryption GCM: %w", err)
	}

	nonce := data[:totpNonceSize]
	plaintext, err := gcm.Open(nil, nonce, data[totpNonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}

	return string(plaintext), nil
}

func ValidateTOTPCode(secretBase32, code string, now time.Time, period, digits int) bool {
	code = strings.TrimSpace(code)
	if code == "" || len(code) != digits {
		return false
	}

	secretKey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil || len(secretKey) == 0 {
		return false
	}

	counter := now.Unix() / int64(period)
	for delta := -totpDriftWindow; delta <= totpDriftWindow; delta++ {
		if generateTOTP(secretKey, uint64(counter+int64(delta)), digits) == code {
			return true
		}
	}

	return false
}

func generateTOTP(secret []byte, counter uint64, digits int) string {
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}

	hmacHash := hmac.New(sha1.New, secret)
	hmacHash.Write(counterBytes)
	digest := hmacHash.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	binary := (uint32(digest[offset])&0x7f)<<24 |
		(uint32(digest[offset+1])&0xff)<<16 |
		(uint32(digest[offset+2])&0xff)<<8 |
		(uint32(digest[offset+3]) & 0xff)
	otp := binary % uint32(pow10(digits))
	return fmt.Sprintf("%0*d", digits, otp)
}

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, totpRecoveryCodeCount)
	for i := 0; i < totpRecoveryCodeCount; i++ {
		code, err := generateRecoveryCode(totpRecoveryCodeLength)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func generateRecoveryCode(length int) (string, error) {
	var sb strings.Builder
	sb.Grow(length)
	charsetLen := big.NewInt(int64(len(totpRecoveryCharset)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		sb.WriteByte(totpRecoveryCharset[idx.Int64()])
	}

	return sb.String(), nil
}

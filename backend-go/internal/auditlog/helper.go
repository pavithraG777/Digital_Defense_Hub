package auditlog

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type requestContextKey string

const (
	contextKeyIPAddress  requestContextKey = "audit_ip_address"
	contextKeyDeviceName requestContextKey = "audit_device_name"
	contextKeyUserAgent  requestContextKey = "audit_user_agent"
	contextKeySessionID  requestContextKey = "audit_session_id"
)

func WithRequestDetails(
	ctx context.Context,
	ipAddress string,
	deviceName string,
	userAgent string,
	sessionID *uuid.UUID,
) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx = context.WithValue(
		ctx,
		contextKeyIPAddress,
		strings.TrimSpace(ipAddress),
	)

	ctx = context.WithValue(
		ctx,
		contextKeyDeviceName,
		strings.TrimSpace(deviceName),
	)

	ctx = context.WithValue(
		ctx,
		contextKeyUserAgent,
		strings.TrimSpace(userAgent),
	)

	if sessionID != nil {
		ctx = context.WithValue(
			ctx,
			contextKeySessionID,
			*sessionID,
		)
	}

	return ctx
}

func GetRequestIPAddress(
	ctx context.Context,
) string {
	if ctx == nil {
		return ""
	}

	value, ok := ctx.Value(
		contextKeyIPAddress,
	).(string)

	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func GetRequestDeviceName(
	ctx context.Context,
) string {
	if ctx == nil {
		return ""
	}

	value, ok := ctx.Value(
		contextKeyDeviceName,
	).(string)

	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func GetRequestUserAgent(
	ctx context.Context,
) string {
	if ctx == nil {
		return ""
	}

	value, ok := ctx.Value(
		contextKeyUserAgent,
	).(string)

	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func GetRequestSessionID(
	ctx context.Context,
) *uuid.UUID {
	if ctx == nil {
		return nil
	}

	value := ctx.Value(
		contextKeySessionID,
	)

	switch typedValue := value.(type) {
	case uuid.UUID:
		id := typedValue
		return &id

	case *uuid.UUID:
		return typedValue

	case string:
		parsedID, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil {
			return nil
		}

		return &parsedID

	default:
		return nil
	}
}

package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type SecurityNotificationRecipient struct {
	UserID        uuid.UUID
	RecipientName string
	EmailAddress  *string
	PhoneNumber   *string
}

// ListSecurityNotificationRecipients returns active organization users who
// have security-management, threat-view or incident-view access.
//
// SUPER_ADMIN users are always included.
func (r *Repository) ListSecurityNotificationRecipients(
	ctx context.Context,
	organizationID uuid.UUID,
) ([]SecurityNotificationRecipient, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	const query = `
		SELECT DISTINCT
			u.id,
			COALESCE(
				NULLIF(BTRIM(up.display_name), ''),
				NULLIF(
					BTRIM(
						CONCAT_WS(
							' ',
							up.first_name,
							up.last_name
						)
					),
					''
				),
				u.username
			) AS recipient_name,
			NULLIF(
				BTRIM(u.official_email),
				''
			) AS email_address,
			NULLIF(
				BTRIM(up.official_phone),
				''
			) AS phone_number
		FROM users AS u
		LEFT JOIN user_profiles AS up
			ON up.user_id = u.id
		WHERE u.organization_id = $1
			AND u.deleted_at IS NULL
			AND UPPER(u.account_status) = 'ACTIVE'
			AND EXISTS (
				SELECT 1
				FROM user_roles AS ur
				INNER JOIN roles AS r
					ON r.id = ur.role_id
					AND r.deleted_at IS NULL
				LEFT JOIN role_permissions AS rp
					ON rp.role_id = r.id
					AND rp.is_active = TRUE
					AND (
						rp.expires_at IS NULL
						OR rp.expires_at >
							CURRENT_TIMESTAMP
					)
				LEFT JOIN permissions AS p
					ON p.id = rp.permission_id
					AND UPPER(p.status) = 'ACTIVE'
				WHERE ur.user_id = u.id
					AND ur.is_active = TRUE
					AND UPPER(ur.status) = 'ACTIVE'
					AND ur.valid_from <=
						CURRENT_TIMESTAMP
					AND (
						ur.expires_at IS NULL
						OR ur.expires_at >
							CURRENT_TIMESTAMP
					)
					AND (
						UPPER(r.role_code) =
							'SUPER_ADMIN'
						OR UPPER(
							p.permission_code
						) IN (
							'ORGANIZATION_MANAGE_SECURITY',
							'THREAT_VIEW',
							'INCIDENT_VIEW'
						)
					)
			)
		ORDER BY u.id;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list security notification recipients: %w",
			err,
		)
	}
	defer rows.Close()

	recipients := make(
		[]SecurityNotificationRecipient,
		0,
	)

	for rows.Next() {
		var recipient SecurityNotificationRecipient

		if err = rows.Scan(
			&recipient.UserID,
			&recipient.RecipientName,
			&recipient.EmailAddress,
			&recipient.PhoneNumber,
		); err != nil {
			return nil, fmt.Errorf(
				"scan security notification recipient: %w",
				err,
			)
		}

		recipient.RecipientName =
			strings.TrimSpace(
				recipient.RecipientName,
			)

		recipient.EmailAddress =
			normalizeSecurityRecipientValue(
				recipient.EmailAddress,
			)

		recipient.PhoneNumber =
			normalizeSecurityRecipientValue(
				recipient.PhoneNumber,
			)

		recipients = append(
			recipients,
			recipient,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate security notification recipients: %w",
			err,
		)
	}

	return recipients, nil
}

func normalizeSecurityRecipientValue(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.TrimSpace(
		*value,
	)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

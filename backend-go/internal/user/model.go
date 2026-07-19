package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                 uuid.UUID
	OrganizationID     uuid.UUID
	Username           string
	OfficialEmail      string
	PasswordHash       string
	UserType           string
	AccountStatus      string
	EmailVerified      bool
	PhoneVerified      bool
	MFAEnabled         bool
	MustChangePassword bool
	PreferredLanguage  string
	Timezone           string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type UserProfile struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	EmployeeCode  *string
	FirstName     string
	MiddleName    *string
	LastName      *string
	DisplayName   *string
	Designation   *string
	OfficialPhone *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

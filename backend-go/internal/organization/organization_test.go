package organization

import "testing"

func TestValidateOrganizationAdminUniquenessRejectsDuplicateIdentifiers(t *testing.T) {
	request := CreateRequest{
		AdminUsername: "superadmin",
		AdminEmail:    "admin@csl.local",
	}

	existingUsernames := map[string]struct{}{"superadmin": {}}
	existingEmails := map[string]struct{}{"admin@csl.local": {}}

	if err := validateOrganizationAdminUniqueness(request, existingUsernames, existingEmails); err == nil {
		t.Fatal("expected duplicate admin identity to be rejected")
	}
}

func TestValidateOrganizationAdminUniquenessAllowsDistinctIdentifiers(t *testing.T) {
	request := CreateRequest{
		AdminUsername: "alphaadmin",
		AdminEmail:    "alpha-org-admin@alphalabs.example",
	}

	existingUsernames := map[string]struct{}{"superadmin": {}}
	existingEmails := map[string]struct{}{"admin@csl.local": {}}

	if err := validateOrganizationAdminUniqueness(request, existingUsernames, existingEmails); err != nil {
		t.Fatalf("expected distinct admin identity to pass, got: %v", err)
	}
}

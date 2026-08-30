package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestSelectedMFAMethodRequiresExactlyOneCredential(t *testing.T) {
	tests := []struct {
		name    string
		request VerifyMFARequest
		want    string
		wantErr bool
	}{
		{name: "email", request: VerifyMFARequest{EmailCode: "123456"}, want: "EMAIL"},
		{name: "totp", request: VerifyMFARequest{TOTPCode: "123456"}, want: "TOTP"},
		{name: "recovery", request: VerifyMFARequest{RecoveryCode: "RECOVERY01"}, want: "RECOVERY"},
		{name: "missing", request: VerifyMFARequest{}, wantErr: true},
		{name: "ambiguous", request: VerifyMFARequest{EmailCode: "123456", TOTPCode: "654321"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectedMFAMethod(test.request)
			if test.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !test.wantErr && (err != nil || got != test.want) {
				t.Fatalf("got method %q error %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestMatchingRecoveryCodeHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("RECOVERY01"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if got := matchingRecoveryCodeHash([]string{string(hash)}, "RECOVERY01"); got != string(hash) {
		t.Fatal("expected matching recovery hash")
	}
	if got := matchingRecoveryCodeHash([]string{string(hash)}, "WRONGCODE1"); got != "" {
		t.Fatal("unexpected recovery hash match")
	}
}

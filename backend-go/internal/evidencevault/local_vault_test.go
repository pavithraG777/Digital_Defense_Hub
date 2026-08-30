package evidencevault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testVault(t *testing.T) *LocalVault {
	t.Helper()
	vault, err := NewLocalVault(t.TempDir(), "local-key-v1", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	require.NoError(t, err)
	return vault
}

func TestLocalVaultEncryptsAndVerifiesEvidence(t *testing.T) {
	vault := testVault(t)
	org := uuid.New()
	payload := []byte("forensic evidence payload")
	object, err := vault.Put(context.Background(), org, bytes.NewReader(payload), 24*time.Hour)
	require.NoError(t, err)
	stored, _, err := vault.Get(context.Background(), org, object.ObjectID, object.VersionID)
	require.NoError(t, err)
	require.Equal(t, payload, stored)
	raw, err := os.ReadFile(filepath.Join(vault.root, org.String(), object.ObjectID.String(), object.VersionID.String()+".vault"))
	require.NoError(t, err)
	require.NotContains(t, string(raw), string(payload))
}

func TestLocalVaultDetectsCiphertextTampering(t *testing.T) {
	vault := testVault(t)
	org := uuid.New()
	object, err := vault.Put(context.Background(), org, bytes.NewReader([]byte("evidence")), time.Hour)
	require.NoError(t, err)
	path := filepath.Join(vault.root, org.String(), object.ObjectID.String(), object.VersionID.String()+".vault")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	raw[len(raw)-5] ^= 1
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, raw, 0o400))
	_, _, err = vault.Get(context.Background(), org, object.ObjectID, object.VersionID)
	require.Error(t, err)
}

func TestLocalVaultRefusesDeletionDuringRetention(t *testing.T) {
	vault := testVault(t)
	org := uuid.New()
	object, err := vault.Put(context.Background(), org, bytes.NewReader([]byte("evidence")), time.Hour)
	require.NoError(t, err)
	err = vault.Delete(org, object.ObjectID, object.VersionID)
	require.True(t, errors.Is(err, ErrVaultRetained))
}

func TestLocalVaultReadsOldEvidenceAfterKeyRotation(t *testing.T) {
	root := t.TempDir()
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	org := uuid.New()
	oldVault, err := NewLocalVault(root, "key-v1", oldKey)
	require.NoError(t, err)
	object, err := oldVault.Put(context.Background(), org, bytes.NewReader([]byte("historic evidence")), time.Hour)
	require.NoError(t, err)
	rotatedVault, err := NewLocalVault(root, "key-v2", newKey)
	require.NoError(t, err)
	require.NoError(t, rotatedVault.AddDecryptionKey("key-v1", oldKey))
	payload, metadata, err := rotatedVault.Get(context.Background(), org, object.ObjectID, object.VersionID)
	require.NoError(t, err)
	require.Equal(t, []byte("historic evidence"), payload)
	require.Equal(t, "key-v1", metadata.KeyID)
}

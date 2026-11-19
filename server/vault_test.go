package server

import (
	"encoding/json"
	"errors"
	"testing"
)

func vaultFixture(t *testing.T, project string) Vault {
	t.Helper()
	raw, err := json.Marshal(vaultSnapshot{
		ProjectID: project,
		Vault:     "payments",
		Values:    map[string]string{"secret_key": "opaque-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{
		projectBindingName:    "project-1",
		vaultScopeBindingName: "payments",
		vaultBindingName:      string(raw),
	}
	vault := NewVault(Request{RID: 1})
	vault.read = func(rid int64, name string) (*string, error) {
		if rid != 1 {
			t.Fatal("vault lookup lost the request handle")
		}
		value := bindings[name]
		return &value, nil
	}
	return vault
}

func TestVaultGetResolvesSnapshotAndScope(t *testing.T) {
	if _, err := (Request{}).Secret(vaultBindingName); err == nil {
		t.Fatal("public secret lookup returned the private vault snapshot")
	}
	vault := vaultFixture(t, "project-1")
	value, err := vault.Get("secret_key")
	if err != nil || value != "opaque-value" {
		t.Fatalf("vault read failed: %q %v", value, err)
	}
	_, err = vault.Get("absent")
	if err == nil {
		t.Fatal("absent vault secret accepted")
	}
	if failure, ok := errors.AsType[*OperationError](err); ok {
		t.Fatalf("absent vault secret must fail as a plain error: %v", failure)
	}
}

func TestVaultRejectsMissingAndForeignSnapshots(t *testing.T) {
	for _, item := range []struct {
		name  string
		vault Vault
	}{
		{name: "unbound", vault: NewVault(Request{RID: 1})},
		{name: "foreign-project", vault: vaultFixture(t, "project-2")},
	} {
		_, err := item.vault.Get("secret_key")
		failure, ok := errors.AsType[*OperationError](err)
		if !ok || failure.Status != 503 || failure.Code != "service_unavailable" {
			t.Fatalf("%s: got %v", item.name, err)
		}
	}
}

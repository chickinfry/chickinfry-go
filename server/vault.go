package server

import (
	"errors"

	"github.com/chickinfry/chickinfry-go/server/host"
)

const (
	vaultBindingName      = "CHIK_VAULT"
	vaultScopeBindingName = "CHIK_VAULT_SCOPE"
	projectBindingName    = "CHIK_PROJECT_ID"
)

// Vault reads secret values from the request-scoped vault snapshot.
type Vault struct {
	rid      int64
	read     func(int64, string) (*string, error)
	resolved *vaultSnapshot
}

type vaultSnapshot struct {
	ProjectID string            `json:"projectId"`
	Vault     string            `json:"vault"`
	Values    map[string]string `json:"values"`
}

// NewVault defers snapshot resolution to the first read.
func NewVault(request Request) Vault {
	return Vault{rid: request.RID, read: readVaultBinding}
}

// Get returns one declared secret of the vault scope.
func (vault Vault) Get(name string) (string, error) {
	snapshot, err := vault.snapshot()
	if err != nil {
		return "", err
	}
	value, exists := snapshot.Values[name]
	if !exists {
		return "", errors.New("secret is not bound to the vault")
	}
	return value, nil
}

func (vault Vault) snapshot() (*vaultSnapshot, error) {
	if vault.resolved != nil {
		return vault.resolved, nil
	}
	unavailable := &OperationError{Status: 503, Code: "service_unavailable"}
	if vault.read == nil {
		return nil, unavailable
	}
	scope, err := vault.read(vault.rid, vaultScopeBindingName)
	if err != nil || scope == nil || *scope == "" {
		return nil, unavailable
	}
	project, err := vault.read(vault.rid, projectBindingName)
	if err != nil || project == nil || *project == "" {
		return nil, unavailable
	}
	raw, err := vault.read(vault.rid, vaultBindingName)
	if err != nil || raw == nil || *raw == "" {
		return nil, unavailable
	}
	var snapshot vaultSnapshot
	if err := host.Decode([]byte(*raw), &snapshot); err != nil {
		return nil, unavailable
	}
	if snapshot.ProjectID != *project || snapshot.Vault != *scope || snapshot.Values == nil {
		return nil, unavailable
	}
	vault.resolved = &snapshot
	return &snapshot, nil
}

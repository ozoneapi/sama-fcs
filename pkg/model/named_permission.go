package model

import (
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/names"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/permissions"
)

// ConsentURLPermission -
type ConsentURLPermission struct {
	Identifier       string           `json:"specIdentifier"`
	NamedPermissions NamedPermissions `json:"namedPermissions"`
}

// NamedPermission - permission structure
type NamedPermission struct {
	Name                   string                             `json:"name"`
	PermissionSetTestCases permissions.PermissionSetTestCases `json:"codeSet"`
	ConsentURL             string                             `json:"consentUrl"`
}

// NamedPermissions - permission structure
type NamedPermissions []NamedPermission

// Add - to named permissions
func (t *NamedPermissions) Add(token NamedPermission) {
	*t = append(*t, token)
}

// newNamedPermission create a token required to run test cases
// generates a unique name
func newNamedPermission(name string, permissionSet permissions.PermissionSetTestCases) NamedPermission {
	return NamedPermission{
		Name:                   name,
		PermissionSetTestCases: permissionSet,
	}
}

// NewSpecConsentRequirements - create a new SpecConsentRequirements
func NewSpecConsentRequirements(nameGenerator names.Generator, result permissions.PermissionTestCollection, specID string) ConsentURLPermission {
	namedPermissions := NamedPermissions{}
	for _, resultSet := range result {
		namedPermission := newNamedPermission(nameGenerator.Generate(), resultSet)
		namedPermissions = append(namedPermissions, namedPermission)
	}
	return ConsentURLPermission{
		Identifier:       specID,
		NamedPermissions: namedPermissions,
	}
}

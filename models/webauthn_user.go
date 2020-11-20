package models

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gofrs/uuid"
)

// WebAuthNUser represents the user model for the webauthn package
type WebAuthNUser struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

// NewWebAuthNUser creates and returns a new WebAuthNUser
func NewWebAuthNUser(id uuid.UUID, name string, displayName string) *WebAuthNUser {
	user := WebAuthNUser{}
	user.id = id
	user.name = name
	user.displayName = displayName

	return &user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u WebAuthNUser) WebAuthnID() []byte {
	return u.id.Bytes()
}

// WebAuthnName returns the user's username
func (u WebAuthNUser) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u WebAuthNUser) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u WebAuthNUser) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *WebAuthNUser) AddCredential(cred webauthn.Credential) {
	u.credentials = append(u.credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u WebAuthNUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u WebAuthNUser) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

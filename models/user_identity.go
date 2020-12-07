package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// UserIdentity represents a user identity as it appears on a remote service (VPN, SSH)
// and can be different from the user email, but is linked to the User.
type UserIdentity struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID
	Type      string
	Name      string
	PublicKey string
	Validated bool
	CreatedAt time.Time
	User      User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// BeforeCreate ensures the model has an ID before saving it
func (userIdentity *UserIdentity) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	userIdentity.ID = uuid
	return nil
}

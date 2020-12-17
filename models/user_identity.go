package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// UserIdentity represents a user identity as it appears on a remote service (VPN, SSH)
// and can be different from the user email, but is linked to the User.
type UserIdentity struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey"`
	// The composite index ensures that a key can only be tied to 1 User
	UserID         *uuid.UUID `gorm:"uniqueIndex:idx_unique;" json:"-"`
	Type           string     `gorm:"uniqueIndex:idx_unique;not null"`
	Name           string     `gorm:"uniqueIndex:idx_unique;"`
	PublicKey      string     `gorm:"uniqueIndex:idx_unique;"`
	ValidationData string     `json:"-"`
	Validated      bool
	CreatedAt      time.Time
	User           *User `json:"-"`
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

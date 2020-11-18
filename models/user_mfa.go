package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// UserMFA represents a "second factor" authentication provider for a given user
type UserMFA struct {
	ID        uuid.UUID `gorm:"type:uuid;unique"`
	Email     string    `gorm:"primaryKey"`
	Type      string    `gorm:"primaryKey"`
	Data      string    // Provider-specific data
	Validated bool
	CreatedAt time.Time
	User      User `gorm:"primaryKey;foreignKey:Email;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:email"`
}

// BeforeCreate ensures the model has an ID before saving it
func (userMFA *UserMFA) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	userMFA.ID = uuid
	return nil
}

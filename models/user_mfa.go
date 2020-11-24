package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// UserMFA represents a "second factor" authentication provider for a given user
type UserMFA struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID
	Type      string
	Data      string // Provider-specific data. (OTP secret...))
	Validated bool
	CreatedAt time.Time
	ExpiresAt time.Time // Expiration date when validation is pending
	UserAgent string
	User      User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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

func (userMFA *UserMFA) IsValid() bool {
	return userMFA.Validated && time.Now().Before(userMFA.ExpiresAt)
}

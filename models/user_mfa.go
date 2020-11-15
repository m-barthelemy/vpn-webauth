package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// VpnSession represents a successful Google + OTP login
type UserMFA struct {
	// Using `Email` as primary key again ensures a user only has 1 valid "session"
	ID        uuid.UUID `gorm:"type:uuid;unique"`
	Email     string    `gorm:"primaryKey"`
	Type      string    `gorm:"primaryKey"`
	Data      string    // Provider-specific data
	CreatedAt time.Time
	User      User `gorm:"primaryKey;foreignKey:Email;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:email"`
}

func (userMFA *UserMFA) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	userMFA.ID = uuid
	return nil
}

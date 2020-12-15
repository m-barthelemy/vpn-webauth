package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// VpnSession represents a successful Google + OTP login
type RemoteSession struct {
	// Using `Identity` and `Type` as primary key again ensures a user only has 1 valid "session"
	ID        uuid.UUID `gorm:"unique"`
	Type      string    `gorm:"primaryKey"`
	Identity  string    `gorm:"primaryKey"`
	SourceIP  string
	CreatedAt time.Time
	UserID    *uuid.UUID
	User      *User
}

// BeforeCreate ensures the model has an ID before saving it
func (vpnSession *RemoteSession) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	vpnSession.ID = uuid
	return nil
}

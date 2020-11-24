package models

import (
	"time"

	"github.com/gofrs/uuid"
)

// VpnSession represents a successful Google + OTP login
type VpnSession struct {
	// Using `Email` as primary key again ensures a user only has 1 valid "session"
	ID        string
	Email     string `gorm:"primaryKey"`
	SourceIP  string
	MFAID     uuid.UUID `gorm:"type:uuid"`
	CreatedAt time.Time
	// Tying the session to both the User and UserMFA models ensures that all sessions are immediately invalidated
	// if a user or their MFA provider gets deleted
	User    User    `gorm:"primaryKey;foreignKey:Email;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:email"`
	UserMFA UserMFA `gorm:"primaryKey;foreignKey:MFAID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:id"`
}

package models

import (
	"time"
)

// VpnSession represents a successful Google + OTP login
type UserMFA struct {
	// Using `Email` as primary key again ensures a user only has 1 valid "session"
	ID        string
	Email     string `gorm:"primaryKey"`
	Type      string `gorm:"primaryKey"`
	Secret    string
	CreatedAt time.Time
	User      User `gorm:"primaryKey;foreignKey:Email;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:email"`
}

package models

import (
	"time"
)

// VpnSession represents a successful Google + OTP login
type VpnSession struct {
	// Using `Email` as primary key again ensures a user only has 1 valid "session"
	ID        string
	Email     string `gorm:"primaryKey"`
	SourceIP  string
	CreatedAt time.Time
}

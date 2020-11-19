package models

import (
	"time"

	"gorm.io/gorm"
)

// User is a Google account
type User struct {
	gorm.Model
	// Gorm defaults to creating an ID pkey, whereas here the email is unique so it makes a perfect primary key.
	// We need to explicitly declare ID and then set the `primaryKey` tag on the field we choose to override the default behavior.
	ID         int64
	Email      string `gorm:"primaryKey"`
	TotpSecret string // The secret created during the 2FA enrollment (QR code scan)
	CreatedAt  time.Time
	UpdatedAt  time.Time
	MFAs       []UserMFA `gorm:"foreignkey:Email"`
}

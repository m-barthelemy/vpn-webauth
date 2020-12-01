package models

import (
	"time"

	"github.com/gofrs/uuid"
)

// UserSubscription is an authenticated User subscription to web push notifications
type UserSubscription struct {
	UserID     uuid.UUID `gorm:"type:uuid"`
	Hash       string    `gorm:"primaryKey"`
	Data       string
	CreatedAt  time.Time
	LastUsedAt time.Time
	User       User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

//go:generate pkger
package main

import (
	"log"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/routes"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	var config models.Config
	config = config.New()

	err := envconfig.Process("VPNWA", &config)
	if err != nil {
		log.Fatal(err.Error())
	}
	config.Verify()

	var db *gorm.DB
	var dbErr error

	switch strings.ToLower(config.DbType) {
	case "sqlite":
		db, dbErr = gorm.Open(sqlite.Open(config.DbDSN), &gorm.Config{})
	case "postgres":
		db, dbErr = gorm.Open(postgres.Open(config.DbDSN), &gorm.Config{})
	case "mysql":
		db, dbErr = gorm.Open(mysql.Open(config.DbDSN), &gorm.Config{})
	default:
		log.Fatalf("Unknown DbType '%s'", config.DbType)
	}
	if dbErr != nil {
		log.Fatalf("Failed to connect to database: %s", dbErr)
	}

	// Migrate the schema
	if err := db.AutoMigrate(&models.User{}); err != nil {
		log.Fatalf("Failed to run database migrations for User model: %s", err)
	}
	if err := db.AutoMigrate(&models.VpnSession{}); err != nil {
		log.Fatalf("Failed to run database migrations for VpnSession model: %s", err)
	}
	if err := db.AutoMigrate(&models.UserMFA{}); err != nil {
		log.Fatalf("Failed to run database migrations for UserMFA model: %s", err)
	}
	startServer(&config, routes.New(&config, db))

}

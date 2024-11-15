package main

import (
	"log"
	"net/http"

	"github.com/secnex/authentication-api/config"
	"github.com/secnex/authentication-api/database"
	"github.com/secnex/authentication-api/handlers"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if cfg.Environment == "development" {
		// Initialize test user
		if err := database.InitializeTestUser(db); err != nil {
			log.Printf("[WARN] Failed to initialize test user: %v", err)
			// Continue execution even if test user creation fails
		} else {
			log.Printf("[INFO] Test user credentials:")
			log.Printf("[INFO] Username: testuser")
			log.Printf("[INFO] Password: password123")
		}
	}

	// Create router
	router := handlers.NewRouter(db)

	// Start server
	log.Printf("[INFO] Auth-API starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, router); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

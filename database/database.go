package database

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"log"

	_ "github.com/lib/pq"
	"github.com/secnex/authentication-api/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration  = 1 * time.Hour
	RefreshTokenDuration = 24 * time.Hour
)

func Connect(dbURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}

	// Verbindung testen
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func GetUserByToken(db *sql.DB, encodedToken string) (*models.User, error) {
	log.Printf("[DEBUG] Looking up user by token")

	// Decode base64 token
	tokenBytes, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		log.Printf("[ERROR] Invalid token encoding")
		return nil, fmt.Errorf("invalid token encoding")
	}

	// Split decoded token into components
	parts := strings.Split(string(tokenBytes), ":")
	if len(parts) != 2 {
		log.Printf("[ERROR] Invalid token format")
		return nil, fmt.Errorf("invalid token format")
	}

	tokenID := parts[0]
	rawToken := parts[1]

	var user models.User
	var rolesStr string
	var hashedToken string

	// Get user and hashed token
	err = db.QueryRow(`
		SELECT u.id, u.username, u.roles, u.created_at, ut.token
		FROM users u
		JOIN user_tokens ut ON u.id = ut.user_id
		WHERE ut.id = $1 AND ut.expires_at > $2
	`, tokenID, time.Now()).Scan(&user.ID, &user.Username, &rolesStr, &user.CreatedAt, &hashedToken)

	if err != nil {
		log.Printf("[ERROR] Failed to get user by token: %v", err)
		return nil, err
	}

	// Verify token
	if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(rawToken)); err != nil {
		log.Printf("[ERROR] Invalid token hash")
		return nil, fmt.Errorf("invalid token")
	}

	log.Printf("[DEBUG] Found user %s with token", user.Username)
	user.Roles = parseRoles(rolesStr)
	return &user, nil
}

func parseRoles(rolesStr string) []string {
	return strings.Split(rolesStr, ",")
}

func CreateTokenPair(db *sql.DB, userID string) (*models.TokenResponse, error) {
	log.Printf("[DEBUG] Creating token pair for user %s", userID)

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Create refresh token first
	refreshToken := generateSecureToken()
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var refreshTokenID string
	err = tx.QueryRow(`
		INSERT INTO user_tokens (user_id, token, expires_at, token_type)
		VALUES ($1, $2, $3, 'refresh')
		RETURNING id
	`, userID, string(hashedRefreshToken), time.Now().Add(RefreshTokenDuration)).Scan(&refreshTokenID)
	if err != nil {
		return nil, err
	}

	// Create access token
	accessToken := generateSecureToken()
	hashedAccessToken, err := bcrypt.GenerateFromPassword([]byte(accessToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var accessTokenID string
	err = tx.QueryRow(`
		INSERT INTO user_tokens (user_id, token, expires_at, token_type, refresh_token_id)
		VALUES ($1, $2, $3, 'access', $4)
		RETURNING id
	`, userID, string(hashedAccessToken), time.Now().Add(AccessTokenDuration), refreshTokenID).Scan(&accessTokenID)
	if err != nil {
		return nil, err
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Create response
	return &models.TokenResponse{
		AccessToken:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", accessTokenID, accessToken))),
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", refreshTokenID, refreshToken))),
		ExpiresIn:   int64(AccessTokenDuration.Seconds()),
		TokenType:   "Bearer",
	}, nil
}

func RefreshAccessToken(db *sql.DB, encodedRefreshToken string) (*models.TokenResponse, error) {
	log.Printf("[DEBUG] Refreshing access token")

	// Decode and validate refresh token
	tokenBytes, err := base64.StdEncoding.DecodeString(encodedRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}

	parts := strings.Split(string(tokenBytes), ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	refreshTokenID := parts[0]
	rawRefreshToken := parts[1]

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Verify refresh token
	var userID string
	var hashedRefreshToken string
	err = tx.QueryRow(`
		SELECT user_id, token 
		FROM user_tokens 
		WHERE id = $1 AND token_type = 'refresh' AND expires_at > $2
	`, refreshTokenID, time.Now()).Scan(&userID, &hashedRefreshToken)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedRefreshToken), []byte(rawRefreshToken)); err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Create new access token
	accessToken := generateSecureToken()
	hashedAccessToken, err := bcrypt.GenerateFromPassword([]byte(accessToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Delete old access tokens for this refresh token
	_, err = tx.Exec(`
		DELETE FROM user_tokens 
		WHERE refresh_token_id = $1 AND token_type = 'access'
	`, refreshTokenID)
	if err != nil {
		return nil, err
	}

	// Create new access token
	var accessTokenID string
	err = tx.QueryRow(`
		INSERT INTO user_tokens (user_id, token, expires_at, token_type, refresh_token_id)
		VALUES ($1, $2, $3, 'access', $4)
		RETURNING id
	`, userID, string(hashedAccessToken), time.Now().Add(AccessTokenDuration), refreshTokenID).Scan(&accessTokenID)
	if err != nil {
		return nil, err
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", accessTokenID, accessToken))),
		RefreshToken: encodedRefreshToken, // Return the same refresh token
		ExpiresIn:   int64(AccessTokenDuration.Seconds()),
		TokenType:   "Bearer",
	}, nil
}

func ValidateCredentials(db *sql.DB, username, password string) (*models.User, error) {
	log.Printf("[DEBUG] Validating credentials for user %s", username)

	var user models.User
	var passwordHash string
	var rolesStr string

	err := db.QueryRow(`
		SELECT id, username, password_hash, roles, created_at
		FROM users
		WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &passwordHash, &rolesStr, &user.CreatedAt)

	if err != nil {
		log.Printf("[ERROR] User lookup failed for %s: %v", username, err)
		return nil, err
	}

	if !checkPasswordHash(password, passwordHash) {
		log.Printf("[WARN] Invalid password attempt for user %s", username)
		return nil, fmt.Errorf("invalid credentials")
	}

	log.Printf("[DEBUG] Successfully validated credentials for user %s", username)
	user.Roles = parseRoles(rolesStr)
	return &user, nil
}

func InvalidateToken(db *sql.DB, encodedToken string) error {
	// Decode base64 token
	tokenBytes, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return fmt.Errorf("invalid token encoding")
	}

	// Split decoded token into components
	parts := strings.Split(string(tokenBytes), ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid token format")
	}

	tokenID := parts[0]
	rawToken := parts[1]

	// Get hashed token from database
	var hashedToken string
	err = db.QueryRow(`
		SELECT token FROM user_tokens 
		WHERE id = $1
	`, tokenID).Scan(&hashedToken)

	if err != nil {
		return err
	}

	// Verify token before deletion
	if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(rawToken)); err != nil {
		return fmt.Errorf("invalid token")
	}

	// Delete the token
	_, err = db.Exec(`
		DELETE FROM user_tokens
		WHERE id = $1
	`, tokenID)

	return err
}

// Hilfsfunktionen
func generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// InitializeTestUser erstellt einen Test-User, falls dieser noch nicht existiert
func InitializeTestUser(db *sql.DB) error {
	log.Printf("[DEBUG] Checking for test user existence")

	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM users 
			WHERE username = 'testuser'
		)
	`).Scan(&exists)

	if err != nil {
		log.Printf("[ERROR] Failed to check test user existence: %v", err)
		return err
	}

	if exists {
		log.Printf("[DEBUG] Test user already exists")
		return nil
	}

	// Generate password hash for 'password123'
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[ERROR] Failed to generate password hash: %v", err)
		return err
	}

	// Create test user with admin and user roles
	_, err = db.Exec(`
		INSERT INTO users (username, password_hash, roles)
		VALUES ($1, $2, $3)
	`, "testuser", string(passwordHash), "admin,user")

	if err != nil {
		log.Printf("[ERROR] Failed to create test user: %v", err)
		return err
	}

	log.Printf("[INFO] Successfully created test user test@example.com")
	return nil
}

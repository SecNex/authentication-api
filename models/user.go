package models

import "time"

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Roles     []string  `json:"roles"`
	Groups    []string  `json:"groups"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn   int64  `json:"expires_in"` // Seconds until access token expires
	TokenType   string `json:"token_type"` // "Bearer"
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

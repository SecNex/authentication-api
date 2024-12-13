package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/secnex/authentication-api/database"
	"github.com/secnex/authentication-api/models"
)

type Handler struct {
	db *sql.DB
}

func NewRouter(db *sql.DB) http.Handler {
	h := &Handler{db: db}
	r := mux.NewRouter()

	r.HandleFunc("/auth/validate", h.ValidateToken).Methods("GET")
	r.HandleFunc("/auth/login", h.Login).Methods("POST")
	r.HandleFunc("/auth/logout", h.Logout).Methods("POST")
	r.HandleFunc("/auth/refresh", h.RefreshToken).Methods("POST")

	return r
}

func (h *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Processing token validation request from %s", r.RemoteAddr)

	token := extractToken(r)
	if token == "" {
		log.Printf("[WARN] No token provided in request from %s", r.RemoteAddr)
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, expiresAt, err := database.GetUserByToken(h.db, token)
	if err != nil {
		log.Printf("[ERROR] Invalid token from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	log.Printf("[DEBUG] Successfully validated token for user %s", user.Username)
	// Difference in seconds between now and expiresAt - only return seconds until expiration
	diff := time.Until(*expiresAt).Seconds()
	diffInt := int(diff)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": user,
		"exp":  diffInt,
	})
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}
	return ""
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Processing login request from %s", r.RemoteAddr)

	var loginReq models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		log.Printf("[ERROR] Invalid request format from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	log.Printf("[DEBUG] Attempting login for user: %s", loginReq.Username)
	user, err := database.ValidateCredentials(h.db, loginReq.Username, loginReq.Password)
	if err != nil {
		log.Printf("[WARN] Failed login attempt for user %s from %s: %v",
			loginReq.Username, r.RemoteAddr, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokenResponse, err := database.CreateTokenPair(h.db, user.ID)
	if err != nil {
		log.Printf("[ERROR] Failed to create tokens for user %s: %v", user.Username, err)
		http.Error(w, "Error creating tokens", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Successful login for user %s", user.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tokens": tokenResponse,
		"user":   user,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Processing logout request from %s", r.RemoteAddr)

	token := extractToken(r)
	if token == "" {
		log.Printf("[WARN] No token provided for logout from %s", r.RemoteAddr)
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}

	if err := database.InvalidateToken(h.db, token); err != nil {
		log.Printf("[ERROR] Failed to invalidate token: %v", err)
		http.Error(w, "Error during logout", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Successfully logged out token")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully logged out",
	})
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var refreshReq models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshReq); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	tokenResponse, err := database.RefreshAccessToken(h.db, refreshReq.RefreshToken)
	if err != nil {
		log.Printf("[ERROR] Failed to refresh token: %v", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)
}

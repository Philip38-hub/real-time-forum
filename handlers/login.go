package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse JSON request body
		var loginData struct {
			Identifier string `json:"identifier"`
			Password   string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
			SendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		if loginData.Identifier == "" || loginData.Password == "" {
			SendError(w, "Identifier and password are required", http.StatusBadRequest)
			return
		}

		// Determine if identifier is email or nickname
		var user User
		var hashedPassword string
		var err error
		if strings.Contains(loginData.Identifier, "@") {
			// Case-insensitive email comparison using LOWER() function
			err = db.QueryRow("SELECT id, email, nickname, password FROM users WHERE LOWER(email) = LOWER(?)", loginData.Identifier).Scan(
				&user.ID, &user.Email, &user.Nickname, &hashedPassword,
			)
		} else {
			// Case-insensitive nickname comparison using LOWER() function
			err = db.QueryRow("SELECT id, email, nickname, password FROM users WHERE LOWER(nickname) = LOWER(?)", loginData.Identifier).Scan(
				&user.ID, &user.Email, &user.Nickname, &hashedPassword,
			)
		}
		if err == sql.ErrNoRows {
			SendError(w, "Invalid credentials", http.StatusUnauthorized)
			return
		} else if err != nil {
			SendError(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Compare passwords
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginData.Password))
		if err != nil {
			SendError(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Check if the user is already logged in
		var existingSessionID string
		err = db.QueryRow("SELECT session_id FROM sessions WHERE user_id = ?", user.ID).Scan(&existingSessionID)
		if err == nil {
			// Delete existing session
			_, err = db.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
			if err != nil {
				SendError(w, "Database error", http.StatusInternalServerError)
				return
			}
		}

		// Create new session
		sessionID := uuid.New().String()
		_, err = db.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, user.ID)
		if err != nil {
			SendError(w, "Error creating session", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		// Return user data
		user.Password = "" // Remove password from response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"user":    user,
		})
		return
	}

	// If not POST, return error
	SendError(w, "Method not allowed", http.StatusMethodNotAllowed)
}

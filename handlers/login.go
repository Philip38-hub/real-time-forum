package handlers

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Add this at the very start
	log.Println("LoginHandler called. Method:", r.Method)
	log.Println("Request headers:", r.Header)
	if r.Method == http.MethodGet {
		// Show login form
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Printf("Error parsing login template: %v", err)
			RenderError(w, r, "server_error", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, nil)
		if err != nil {
			log.Printf("Error executing login template: %v", err)
			RenderError(w, r, "server_error", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		// Check if the request wants JSON response
		// Modify your wantsJSON check
		wantsJSON := r.Header.Get("X-Requested-With") == "XMLHttpRequest"
		log.Printf("Wants JSON: %v, Content-Type: %s", wantsJSON, r.Header.Get("Content-Type"))
		email := r.FormValue("email")
		password := r.FormValue("password")

		if email == "" || password == "" {
			if wantsJSON {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "Invalid input",
				})
			} else {
				RenderError(w, r, "invalid_input", http.StatusBadRequest)
			}
			return
		}

		// Get user from database
		var user User
		var hashedPassword string
		err := db.QueryRow("SELECT id, email, nickname, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.Username, &hashedPassword)
		if err == sql.ErrNoRows {
			RenderError(w, r, "invalid_credentials", http.StatusUnauthorized)
			return
		} else if err != nil {
			log.Printf("Database error during login: %v", err)
			RenderError(w, r, "database_error", http.StatusInternalServerError)
			return
		}

		// Compare passwords
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			RenderError(w, r, "invalid_credentials", http.StatusUnauthorized)
			return
		}

		// Check if the user is already logged in
		var existingSessionID string
		err = db.QueryRow("SELECT session_id FROM sessions WHERE user_id = ?", user.ID).Scan(&existingSessionID)
		if err == nil {
			_, err = db.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
			if err != nil {
				log.Printf("Error deleting existing session: %v", err)
				RenderError(w, r, "database_error", http.StatusInternalServerError)
				return
			}
		}

		// Create session
		sessionID := uuid.New().String()
		_, err = db.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, user.ID)
		if err != nil {
			log.Printf("Error creating session: %v", err)
			if wantsJSON {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "Database error",
				})
			} else {
				RenderError(w, r, "database_error", http.StatusInternalServerError)
			}
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		})

		if wantsJSON {
			// Send JSON response for API calls
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"session_id": sessionID,
				"user_id":    user.ID,
				"username":   user.Username,
			})
			log.Printf("Sending login response: UserID=%s, Username=%s", user.ID, user.Username)
		} else {
			// Redirect for regular form submissions
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return

	}

	RenderError(w, r, "invalid_input", http.StatusMethodNotAllowed)
}

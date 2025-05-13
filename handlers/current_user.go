package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
)

func CurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Debug logging
	log.Printf("CurrentUserHandler: Starting request handling")

	// Extract and validate session_id from HttpOnly cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Printf("CurrentUserHandler: No session cookie found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Printf("CurrentUserHandler: Found session_id: %s", cookie.Value)

	// Verify db connection
	if db == nil {
		log.Printf("CurrentUserHandler: Database connection is nil")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "Database connection not initialized",
			"authenticated": false,
		})
		return
	}

	// Fetch user information from the database based on session_id
	var userID, nickname string
	query := `
		SELECT u.id, u.nickname
		FROM users u
		JOIN sessions s ON u.id = s.user_id
		WHERE s.session_id = ?`

	err = db.QueryRow(query, cookie.Value).Scan(&userID, &nickname)

	if err == sql.ErrNoRows {
		log.Printf("CurrentUserHandler: No valid session found in database")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "Session expired or invalid",
			"authenticated": false,
		})
		return
	} else if err != nil {
		log.Printf("CurrentUserHandler: Database error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "Internal server error",
			"authenticated": false,
		})
		return
	}

	log.Printf("CurrentUserHandler: Successfully found user: ID=%s, nickname=%s", userID, nickname)

	// Return user information as JSON
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"userId":        userID,
		"nickname":      nickname,
		"authenticated": true,
	})
}

package handlers

import (
	"encoding/json"
	"net/http"
)

func CurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	// Extract and validate session_id from HttpOnly cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch user information from the database based on session_id
	var userID, username string
	err = db.QueryRow(`
        SELECT u.id, u.username
        FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.session_id = ?
    `, cookie.Value).Scan(&userID, &username)
	if err != nil {
		http.Error(w, "Failed to fetch profile", http.StatusUnauthorized)
		return
	}

	// Return user information as JSON
	response := map[string]string{
		"userId":   userID,
		"username": username,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

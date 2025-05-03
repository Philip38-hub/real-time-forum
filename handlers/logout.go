package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the session cookie
	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		// Delete the session from the database
		_, err = db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionCookie.Value)
		if err != nil {
			http.Error(w, "Error deleting session", http.StatusInternalServerError)
			return
		}

		// Expire the cookie by setting it to a past date
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	// Return a JSON response instead of redirecting
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
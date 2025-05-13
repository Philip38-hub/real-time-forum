package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle POST requests
	if r.Method != http.MethodPost {
		RenderError(w, r, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the session cookie
	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		log.Printf("LogoutHandler: Found session_id: %s", sessionCookie.Value)

		// Get user ID from session
		var userID string
		err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionCookie.Value).Scan(&userID)
		if err == nil && userID != "" {
			// Broadcast user offline status
			BroadcastUserStatus(userID, false)

			// Close any existing WebSocket connection
			clientsMutex.Lock()
			if conn, exists := clients[userID]; exists {
				conn.Close()
				delete(clients, userID)
			}
			clientsMutex.Unlock()
		}

		// Delete the session from the database
		_, err = db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionCookie.Value)
		if err != nil {
			HandleDatabaseError(w, r, err)
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

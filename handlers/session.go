package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
)

// GetSession retrieves the session based on the session cookie
func GetSession(r *http.Request) (*Session, error) {
	// Get session cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Printf("Session cookie error: %v", err)
		return nil, err
	}

	// Validate the session token
	return ValidateSessionToken(cookie.Value)
}

// ValidateSessionToken checks if a session token is valid and returns session details
func ValidateSessionToken(sessionID string) (*Session, error) {
	// Check if session ID is empty
	if sessionID == "" {
		return nil, errors.New("empty session ID")
	}

	// Prepare SQL query to find a valid session     // nickname
	query := `
		SELECT 
			s.session_id, 
			s.user_id,
			u.nickname,   
			u.email
		FROM 
			sessions s
		JOIN 
			users u ON s.user_id = u.id
		WHERE 
			s.session_id = ?`

	// Execute query
	var session Session
	var nickname, email string
	err := db.QueryRow(query, sessionID).Scan(
		&session.SessionID,
		&session.UserID,
		&nickname,
		&email,
	)
	// Handle potential errors
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid session token")
		}
		log.Printf("Database error validating session: %v", err)
		return nil, errors.New("database error during session validation")
	}

	return &session, nil
}

// InvalidateSession removes a user's session
func InvalidateSession(userID string) error {
	query := `DELETE FROM sessions WHERE user_id = ?`

	_, err := db.Exec(query, userID)
	if err != nil {
		log.Printf("Error invalidating session: %v", err)
		return err
	}

	return nil
}

// SetupSessionTables creates the necessary database table for sessions
func SetupSessionTables() {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id)
	)`)
	if err != nil {
		log.Fatalf("Error creating sessions table: %v", err)
	}

	// Create index for faster lookups
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id 
	                 ON sessions(user_id)`)
	if err != nil {
		log.Printf("Error creating sessions user_id index: %v", err)
	}
}

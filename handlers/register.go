package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var registerData struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Age       int    `json:"age"`
		Gender    string `json:"gender"`
		Email     string `json:"email"`
		Nickname  string `json:"nickname"` 
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registerData); err != nil {
		SendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate input
	registerData.Email = strings.TrimSpace(registerData.Email)
	registerData.Nickname = strings.TrimSpace(registerData.Nickname)
	registerData.Password = strings.TrimSpace(registerData.Password)
	registerData.FirstName = strings.TrimSpace(registerData.FirstName)
	registerData.LastName = strings.TrimSpace(registerData.LastName)

	if registerData.FirstName == "" || registerData.LastName == "" ||
		registerData.Email == "" || registerData.Nickname == "" ||
		registerData.Password == "" || registerData.Gender == "" {
		SendError(w, "All fields are required", http.StatusBadRequest)
		return
	}

	if registerData.Age < 13 {
		SendError(w, "You must be at least 13 years old", http.StatusBadRequest)
		return
	}

	if registerData.Gender != "male" && registerData.Gender != "female" {
		SendError(w, "Invalid gender selection", http.StatusBadRequest)
		return
	}

	// Check existing email
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", registerData.Email).Scan(&count)
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		SendError(w, "Email already registered", http.StatusConflict)
		return
	}

	// Check existing nickname (stored as nickname in DB)
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE nickname = ?", registerData.Nickname).Scan(&count)
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		SendError(w, "Nickname already taken", http.StatusConflict)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerData.Password), bcrypt.DefaultCost)
	if err != nil {
		SendError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Create user ID
	userID := uuid.New().String()

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Insert new user
	_, err = tx.Exec(
		`INSERT INTO users 
        (id, first_name, last_name, age, gender, email, nickname, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		registerData.FirstName,
		registerData.LastName,
		registerData.Age,
		registerData.Gender,
		registerData.Email,
		registerData.Nickname,
		string(hashedPassword),
	)
	if err != nil {
		SendError(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := uuid.New().String()
	_, err = tx.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, userID)
	if err != nil {
		SendError(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/login",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Return success response with user data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user": map[string]interface{}{
			"id":        userID,
			"firstName": registerData.FirstName,
			"lastName":  registerData.LastName,
			"email":     registerData.Email,
			"nickname":  registerData.Nickname,
		},
	})
}

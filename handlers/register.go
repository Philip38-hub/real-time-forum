package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Username validation regex - starts with a letter, 3-30 chars, only allowed characters
var usernameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{2,29}$`)

// List of reserved usernames that should not be allowed
var reservedUsernames = map[string]bool{
	"admin":         true,
	"administrator": true,
	"moderator":     true,
	"mod":           true,
	"support":       true,
	"help":          true,
	"system":        true,
	"official":      true,
	"staff":         true,
	"root":          true,
}

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

	// Validate email format
	if !emailRegex.MatchString(registerData.Email) {
		SendError(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Validate nickname/username format
	if !usernameRegex.MatchString(registerData.Nickname) {
		SendError(w,
			"Invalid username format. Username must start with a letter, contain only letters, numbers, underscores, periods, and hyphens, and be between 3-30 characters.",
			http.StatusBadRequest)
		return
	}

	// Check if nickname contains @ symbol
	if strings.Contains(registerData.Nickname, "@") {
		SendError(w, "Username cannot contain @ symbol", http.StatusBadRequest)
		return
	}

	// Check if nickname is a reserved word
	if reservedUsernames[strings.ToLower(registerData.Nickname)] {
		SendError(w, "This username is reserved and cannot be used", http.StatusBadRequest)
		return
	}

	// Validate password length
	if len(registerData.Password) < 8 {
		SendError(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	// Check existing email (case insensitive)
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?)", registerData.Email).Scan(&count)
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	if count > 0 {
		SendError(w, "Email already registered", http.StatusConflict)
		return
	}

	// Check existing nickname (case insensitive)
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(nickname) = LOWER(?)", registerData.Nickname).Scan(&count)
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	if count > 0 {
		SendError(w, "Username already taken", http.StatusConflict)
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
		registerData.Nickname, // Keep original case for display purposes
		string(hashedPassword),
	)
	if err != nil {
		SendError(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}

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

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

    // Parse JSON request body
    var registerData struct {
        Email    string `json:"email"`
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&registerData); err != nil {
        SendError(w, "Invalid request format", http.StatusBadRequest)
        return
    }

    // Validate input
    registerData.Email = strings.TrimSpace(registerData.Email)
    registerData.Username = strings.TrimSpace(registerData.Username)
    registerData.Password = strings.TrimSpace(registerData.Password)

    if registerData.Email == "" || registerData.Username == "" || registerData.Password == "" {
        SendError(w, "All fields are required", http.StatusBadRequest)
        return
    }

    // Check if email already exists
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

    // Check if username already exists
    err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", registerData.Username).Scan(&count)
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
        "INSERT INTO users (id, email, username, password) VALUES (?, ?, ?, ?)",
        userID, registerData.Email, registerData.Username, string(hashedPassword),
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
        Path:     "/",
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
    })

    // Return success response with user data
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "user": User{
            ID:       userID,
            Email:    registerData.Email,
            Username: registerData.Username,
        },
    })
}

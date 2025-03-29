package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Message request and response structures
type MessageRequest struct {
	ReceiverId string `json:"receiverId"`
	Content    string `json:"content"`
}

type MessageResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	MessageId int64       `json:"messageId,omitempty"`
	Messages  []ChatMessage `json:"messages,omitempty"`
	Users     interface{} `json:"users,omitempty"`
}

// GetUsersHandler returns a list of all users
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get users from database
	users, err := GetUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Get unread counts for current user
	unreadCounts, err := GetUnreadMessageCount(session.UserID)
	if err != nil {
		log.Printf("Error getting unread counts: %v", err)
	}

	// Add unread count to each user
	for i, user := range users {
		userId := user["id"].(string)
		if count, exists := unreadCounts[userId]; exists {
			users[i]["unread"] = count
		} else {
			users[i]["unread"] = 0
		}
	}

	// Send response
	response := MessageResponse{
		Success: true,
		Users:   users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetMessagesHandler returns messages between current user and another user
func GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	if path == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	// Parse pagination parameters
	page := 1
	limit := 10

	pageStr := r.URL.Query().Get("page")
	if pageStr != "" {
		pageVal, err := strconv.Atoi(pageStr)
		if err == nil && pageVal > 0 {
			page = pageVal
		}
	}

	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		limitVal, err := strconv.Atoi(limitStr)
		if err == nil && limitVal > 0 && limitVal <= 100 {
			limit = limitVal
		}
	}

	// Get messages
	messages, err := GetMessages(session.UserID, path, page, limit)
	if err != nil {
		log.Printf("Error getting messages: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Send response
	response := MessageResponse{
		Success:  true,
		Messages: messages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// SendMessageHandler handles message sending via HTTP (as fallback if WebSocket fails)
func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var msgRequest MessageRequest
	err = json.NewDecoder(r.Body).Decode(&msgRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate message
	if msgRequest.ReceiverId == "" || msgRequest.Content == "" {
		http.Error(w, "Receiver ID and content are required", http.StatusBadRequest)
		return
	}

	// Get sender's username
	senderName, err := GetUsernameById(session.UserID)
	if err != nil {
		log.Printf("Error getting sender username: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Create message
	message := ChatMessage{
		SenderId:   session.UserID,
		SenderName: senderName,
		ReceiverId: msgRequest.ReceiverId,
		Content:    msgRequest.Content,
		Timestamp:  time.Now(),
		IsRead:     false,
	}

	// Save message to database
	messageId, err := SaveMessage(message)
	if err != nil {
		log.Printf("Error saving message: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Set message ID
	message.ID = messageId

	// Try to send via WebSocket if recipient is online
	clientsMutex.Lock()
	_, isOnline := clients[msgRequest.ReceiverId]
	clientsMutex.Unlock()

	if isOnline {
		go SendToUser(msgRequest.ReceiverId, "privateMessage", message)
	}

	// Send response
	response := MessageResponse{
		Success:   true,
		Message:   "Message sent",
		MessageId: messageId,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// MarkMessageAsReadHandler marks a message as read
func MarkMessageAsReadHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse message ID from request
	messageIdStr := r.URL.Query().Get("messageId")
	messageId, err := strconv.ParseInt(messageIdStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	// Mark message as read
	err = MarkMessageAsRead(messageId)
	if err != nil {
		log.Printf("Error marking message as read: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Send response
	response := MessageResponse{
		Success: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// SaveMessage stores a private message in the database
func SaveMessage(message ChatMessage) (int64, error) {
	query := `INSERT INTO private_messages 
              (sender_id, receiver_id, content, timestamp, is_read) 
              VALUES (?, ?, ?, ?, ?)`

	stmt, err := db.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	result, err := stmt.Exec(
		message.SenderId,
		message.ReceiverId,
		message.Content,
		message.Timestamp,
		message.IsRead,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// MarkMessageAsRead marks a message as read
func MarkMessageAsRead(messageId int64) error {
	query := `UPDATE private_messages SET is_read = true WHERE id = ?`

	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(messageId)
	return err
}

// GetMessages retrieves messages between two users with pagination
func GetMessages(userId1 string, userId2 string, page int, limit int) ([]ChatMessage, error) {
	offset := (page - 1) * limit

	query := `SELECT pm.id, pm.sender_id, u.nickname, pm.receiver_id, pm.content, pm.timestamp, pm.is_read 
	          FROM private_messages pm
	          JOIN users u ON pm.sender_id = u.id
	          WHERE (pm.sender_id = ? AND pm.receiver_id = ?) 
	             OR (pm.sender_id = ? AND pm.receiver_id = ?)
	          ORDER BY pm.timestamp DESC
	          LIMIT ? OFFSET ?`

	rows, err := db.Query(query, userId1, userId2, userId2, userId1, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []ChatMessage
	for rows.Next() {
		var msg ChatMessage
		err := rows.Scan(&msg.ID, &msg.SenderId, &msg.SenderName, &msg.ReceiverId, &msg.Content, &msg.Timestamp, &msg.IsRead)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

// GetUnreadMessageCount gets the count of unread messages for a user
func GetUnreadMessageCount(userId string) (map[string]int, error) {
	query := `SELECT sender_id, COUNT(*) as count 
	          FROM private_messages 
	          WHERE receiver_id = ? AND is_read = false
	          GROUP BY sender_id`

	rows, err := db.Query(query, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var senderId string
		var count int
		err := rows.Scan(&senderId, &count)
		if err != nil {
			return nil, err
		}
		counts[senderId] = count
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return counts, nil
}

// GetUsernameById retrieves a username by user ID
func GetUsernameById(userId string) (string, error) {
	var username string
	err := db.QueryRow("SELECT nickname FROM users WHERE id = ?", userId).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("user not found")
		}
		return "", err
	}
	return username, nil
}

// GetUsers gets all registered users
func GetUsers() ([]map[string]interface{}, error) {
	query := `SELECT id, nickname FROM users`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}

	for rows.Next() {
		var id string
		var nickname string

		err := rows.Scan(&id, &nickname)
		if err != nil {
			return nil, err
		}

		// Check if user is online
		clientsMutex.Lock()
		_, isOnline := clients[id]
		clientsMutex.Unlock()

		user := map[string]interface{}{
			"id":       id,
			"nickname": nickname,
			"online":   isOnline,
		}

		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

// // GetUserIdFromSession retrieves the user ID from the session cookie
// func GetUserIdFromSession(w http.ResponseWriter, r *http.Request) (string, error) {
// 	// Get session cookie from request
// 	sessionCookie, err := r.Cookie("session_id")
// 	if err != nil {
// 		// No cookie or invalid cookie
// 		return "", nil // Return empty string with no error, user is not logged in
// 	}

// 	// Query to retrieve user_id based on session_id
// 	var userID string
// 	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionCookie.Value).Scan(&userID)
// 	if err == sql.ErrNoRows {
// 		// Session is invalid, clear the cookie
// 		http.SetCookie(w, &http.Cookie{
// 			Name:     "session_id",
// 			Value:    "",
// 			Path:     "/",
// 			Expires:  time.Unix(0, 0), // Expire the cookie immediately
// 			MaxAge:   -1,
// 			HttpOnly: true,
// 			Secure:   true, // Ensure it works only over HTTPS
// 		})
// 		return "", nil // No valid session, user is not logged in
// 	} else if err != nil {
// 		// Database error
// 		http.Error(w, "Database error", http.StatusInternalServerError)
// 		return "", err
// 	}

// 	// Return user ID if session is valid
// 	return userID, nil
// }

// func GetSession(r *http.Request) (*Session, error) {
//     cookie, err := r.Cookie("session_token")
//     if err != nil {
//         log.Printf("Session cookie error: %v", err)
//         return nil, err
//     }

//     session, err := ValidateSessionToken(cookie.Value)
//     if err != nil {
//         log.Printf("Session validation error: %v", err)
//         return nil, err
//     }

//     return session, nil
// }

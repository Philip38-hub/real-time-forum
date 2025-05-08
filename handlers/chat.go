package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	Success   bool          `json:"success"`
	Message   string        `json:"message,omitempty"`
	MessageId int64         `json:"messageId,omitempty"`
	Messages  []ChatMessage `json:"messages,omitempty"`
	Users     interface{}   `json:"users,omitempty"`
}

// GetUsersHandler returns a list of all users
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Validate HTTP method
	if r.Method != http.MethodGet {
		RenderError(w, r, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get users from database
	users, err := GetUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
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

	// Get last message timestamps for current user
	lastMessageTimes, err := GetLastMessageTimes(session.UserID)
	if err != nil {
		log.Printf("Error getting last message times: %v", err)
	}

	// Add last message time to each user
	for i, user := range users {
		userId := user["id"].(string)
		if timestamp, exists := lastMessageTimes[userId]; exists {
			users[i]["lastMessageTime"] = timestamp
		}
	}

	// Send response
	response := MessageResponse{
		Success: true,
		Users:   users,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}
}

// GetMessagesHandler returns messages between current user and another user
func GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	if path == "" {
		RenderError(w, r, "missing_fields", http.StatusBadRequest)
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
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}

	// Send response
	response := MessageResponse{
		Success:  true,
		Messages: messages,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}
}

// SendMessageHandler handles message sending via HTTP (as fallback if WebSocket fails)
func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check method
	if r.Method != http.MethodPost {
		RenderError(w, r, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var msgRequest MessageRequest
	err = json.NewDecoder(r.Body).Decode(&msgRequest)
	if err != nil {
		RenderError(w, r, "invalid_input", http.StatusBadRequest)
		return
	}

	// Validate message
	if msgRequest.ReceiverId == "" || msgRequest.Content == "" {
		log.Printf("Receiver ID and content are required")
		RenderError(w, r, "missing_fields", http.StatusBadRequest)
		return
	}

	// Get sender's nickname
	senderName, err := GetNicknameById(session.UserID)
	if err != nil {
		log.Printf("Error getting sender nickname: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
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
		RenderError(w, r, "server_error", http.StatusInternalServerError)
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}
}

// MarkMessageAsReadHandler marks a message as read
func MarkMessageAsReadHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, err := GetSession(r)
	if err != nil || session.UserID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse message ID from request
	messageIdStr := r.URL.Query().Get("messageId")
	messageId, err := strconv.ParseInt(messageIdStr, 10, 64)
	if err != nil {
		RenderError(w, r, "invalid_input", http.StatusBadRequest)
		return
	}

	// Mark message as read
	err = MarkMessageAsRead(messageId)
	if err != nil {
		log.Printf("Error marking message as read: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}

	// Send response
	response := MessageResponse{
		Success: true,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}
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

// GetNicknameById retrieves a nickname by user ID
func GetNicknameById(userId string) (string, error) {
	var nickname string
	err := db.QueryRow("SELECT nickname FROM users WHERE id = ?", userId).Scan(&nickname)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("user not found")
		}
		return "", err
	}
	return nickname, nil
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

// GetLastMessageTimes retrieves the most recent message timestamps for a given user.
// It returns a map where the keys are the IDs of other users who have communicated
// with the specified user, and the values are the timestamps of the last message
// exchanged with each of those users.
func GetLastMessageTimes(userId string) (map[string]time.Time, error) {
	query := `
    SELECT 
        CASE 
            WHEN sender_id = ? THEN receiver_id 
            ELSE sender_id 
        END as other_user_id,
        MAX(timestamp) as last_timestamp
    FROM private_messages
    WHERE sender_id = ? OR receiver_id = ?
    GROUP BY other_user_id
    ORDER BY last_timestamp DESC
    `

	rows, err := db.Query(query, userId, userId, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	timestamps := make(map[string]time.Time)
	for rows.Next() {
		var otherUserId string
		var timestampStr string

		err := rows.Scan(&otherUserId, &timestampStr)
		if err != nil {
			return nil, err
		}

		// Parse with the exact format including nanoseconds and timezone
		const layout = "2006-01-02 15:04:05.999999999-07:00"
		timestamp, err := time.Parse(layout, timestampStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp '%s': %v", timestampStr, err)
		}

		timestamps[otherUserId] = timestamp
	}

	return timestamps, nil
}

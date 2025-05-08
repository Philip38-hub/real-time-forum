package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	// Configure the upgrader
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all connections
		},
	}

	// Store active connections
	clients      = make(map[string]*websocket.Conn)
	clientsMutex = sync.Mutex{}
)

// Message represents the structure of WebSocket messages
type WSMessage struct {
	Type    string      `json:"type"`    // "newMessage", "newComment", "newLike", etc.
	Content interface{} `json:"content"` // The actual data
}

// ChatMessage represents a private message
type ChatMessage struct {
	ID         int64     `json:"id"`
	SenderId   string    `json:"senderId"`
	SenderName string    `json:"senderName"`
	ReceiverId string    `json:"receiverId"`
	Content    string    `json:"content"`
	Timestamp  time.Time `json:"timestamp"`
	IsRead     bool      `json:"isRead"`
}

// WebSocketHandler handles WebSocket connections
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate session
	var userID string
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", cookie.Value).Scan(&userID)
	if err != nil {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		return
	}
	defer conn.Close()

	// Register the new client with user ID
	clientsMutex.Lock()
	// Remove old connection if exists
	if oldConn, exists := clients[userID]; exists {
		delete(clients, userID)
		if oldConn != conn {
			oldConn.Close()
		}
	}

	clients[userID] = conn

	log.Printf("User %s connected! Total users: %d", userID, len(clients))
	clientsMutex.Unlock()

	// Notify other users that this user is online
	BroadcastUserStatus(userID, true)

	// Remove client when connection closes
	defer func() {
		clientsMutex.Lock()
		delete(clients, userID)
		log.Printf("User %s disconnected! Total users: %d", userID, len(clients))
		clientsMutex.Unlock()

		// Notify other users that this user is offline
		BroadcastUserStatus(userID, false)
	}()

	// Main message loop
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}

		// Parse the message
		var wsMsg WSMessage
		if err := json.Unmarshal(msg, &wsMsg); err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		// Handle different message types
		switch wsMsg.Type {
		case "privateMessage":
			HandlePrivateMessage(wsMsg.Content, userID)
		case "typingIndicator":
			// Handle typing indicators
			HandleTypingIndicator(wsMsg.Content, userID)
		case "readReceipt":
			// Handle read receipts
			HandleReadReceipt(wsMsg.Content, userID)
		default:
			log.Printf("Unknown message type: %s", wsMsg.Type)
		}
	}
}

// BroadcastMessage sends a message to all connected clients
func BroadcastMessage(messageType string, content interface{}) {
	message := WSMessage{
		Type:    messageType,
		Content: content,
	}

	// Marshal the message to JSON
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling message: %v", err)
		return
	}

	// Send to all clients
	clientsMutex.Lock()
	log.Printf("Broadcasting to %d clients", len(clients)) // 🔹 Log number of clients
	for userID, conn := range clients {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Error sending message: %v", err)
			conn.Close()
			delete(clients, userID)
		}
	}
	log.Printf("🔹 Remaining clients after cleanup: %d", len(clients))
	clientsMutex.Unlock()
}

// SendToUser sends a message to a specific user
func SendToUser(userId string, messageType string, content interface{}) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	conn, exists := clients[userId]
	if !exists {
		log.Printf("User %s not connected", userId)
		return
	}

	message := WSMessage{
		Type:    messageType,
		Content: content,
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling message: %v", err)
		return
	}

	err = conn.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		log.Printf("Error sending message to user %s: %v", userId, err)
		conn.Close()
		delete(clients, userId)
	}
}

// BroadcastUserStatus notifies all users about a user's online status
func BroadcastUserStatus(userId string, isOnline bool) {
	message := WSMessage{
		Type: "userStatus",
		Content: map[string]interface{}{
			"userId": userId,
			"online": isOnline,
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling status message: %v", err)
		return
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for user_id, client := range clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Error sending status message: %v", err)
			client.Close()
			delete(clients, user_id)
		}
	}
}

// HandlePrivateMessage processes and delivers a private message
func HandlePrivateMessage(content interface{}, senderId string) {
	// Convert content to map
	contentMap, ok := content.(map[string]interface{})
	if !ok {
		log.Printf("Invalid message content format")
		return
	}

	// Extract message details
	receiverId, ok := contentMap["receiverId"].(string)
	if !ok {
		log.Printf("Invalid receiver ID")
		return
	}

	messageContent, ok := contentMap["content"].(string)
	if !ok {
		log.Printf("Invalid message content")
		return
	}

	// Get sender's nickname
	senderName, err := GetNicknameById(senderId)
	if err != nil {
		log.Printf("Error getting sender nickname: %v", err)
		return
	}

	// Create message struct
	now := time.Now()
	message := ChatMessage{
		SenderId:   senderId,
		SenderName: senderName,
		ReceiverId: receiverId,
		Content:    messageContent,
		Timestamp:  now,
		IsRead:     false,
	}

	// Save message to database
	messageId, err := SaveMessage(message)
	if err != nil {
		log.Printf("Error saving message: %v", err)
		return
	}
	message.ID = messageId

	// Send message to recipient if online
	SendToUser(receiverId, "privateMessage", message)

	// Send confirmation back to sender
	SendToUser(senderId, "messageSent", message)
}

// HandleTypingIndicator processes typing indicators
func HandleTypingIndicator(content interface{}, senderId string) {
	contentMap, ok := content.(map[string]interface{})
	if !ok {
		return
	}

	receiverId, ok := contentMap["receiverId"].(string)
	if !ok {
		return
	}

	isTyping, ok := contentMap["isTyping"].(bool)
	if !ok {
		return
	}

	// Send typing indicator to recipient
	SendToUser(receiverId, "typingIndicator", map[string]interface{}{
		"senderId": senderId,
		"isTyping": isTyping,
	})
}

// HandleReadReceipt processes read receipts
func HandleReadReceipt(content interface{}, userId string) {
	contentMap, ok := content.(map[string]interface{})
	if !ok {
		return
	}

	senderId, ok := contentMap["senderId"].(string)
	if !ok {
		return
	}

	// Mark messages as read in database
	query := `UPDATE private_messages 
			  SET is_read = true 
			  WHERE sender_id = ? AND receiver_id = ? AND is_read = false`

	stmt, err := db.Prepare(query)
	if err != nil {
		log.Printf("Error preparing statement: %v", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(senderId, userId)
	if err != nil {
		log.Printf("Error marking messages as read: %v", err)
		return
	}

	// Notify sender that messages were read
	SendToUser(senderId, "readReceipt", map[string]interface{}{
		"readerId":  userId,
		"senderId":  senderId,
		"timestamp": time.Now(),
	})
}

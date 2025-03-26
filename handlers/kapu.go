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

	// Store active connections mapped to user IDs
	clients      = make(map[*websocket.Conn]string) // conn -> userID
	userConns    = make(map[string]*websocket.Conn) // userID -> conn
	clientsMutex = sync.RWMutex{}
)

// AuthMessage represents authentication message
type AuthMessage struct {
	Type     string `json:"type"`
	UserId   string `json:"userId"`
	Username string `json:"username"`
}

// Message represents the structure of WebSocket messages
type WSMessage struct {
	Type    string      `json:"type"`    // "new_post", "new_comment", "new_like", etc.
	Content interface{} `json:"content"` // The actual data
}

// PrivateMessage represents a message sent between users
type PrivateMessage struct {
	ID         int64     `json:"id"`
	SenderId   string    `json:"senderId"`
	Sender     string    `json:"sender"` // Sender's username
	ReceiverId string    `json:"receiverId"`
	Content    string    `json:"content"`
	Timestamp  time.Time `json:"timestamp"`
}

// WebSocketHandler handles WebSocket connections
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("WebSocket connection attempt from %s", r.RemoteAddr)
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		return
	}
	defer conn.Close()

	// Wait for authentication message
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Error reading WebSocket message (type %d): %v", messageType, err)
		return
	}

	log.Printf("Received auth message: %s", string(message))

	// Parse auth message
	var authMsg AuthMessage
	if err := json.Unmarshal(message, &authMsg); err != nil {
		log.Printf("Error parsing auth message: %v", err)
		return
	}

	if authMsg.Type != "auth" || authMsg.UserId == "" {
		log.Printf("Invalid auth message")
		return
	}

	userId := authMsg.UserId

	// Register the new client with user ID
	clientsMutex.Lock()
	// Remove old connection if exists
	if oldConn, exists := userConns[userId]; exists {
		delete(clients, oldConn)
		// Don't close here as it might be the same connection
		if oldConn != conn {
			oldConn.Close()
		}
	}

	clients[conn] = userId
	userConns[userId] = conn

	log.Printf("User %s connected! Total users: %d", userId, len(userConns))
	clientsMutex.Unlock()

	// Notify other users that this user is online
	BroadcastUserStatus(userId, true)

	// Remove client when connection closes
	defer func() {
		clientsMutex.Lock()
		delete(clients, conn)
		delete(userConns, userId)
		log.Printf("User %s disconnected! Total users: %d", userId, len(userConns))
		clientsMutex.Unlock()

		// Notify other users that this user is offline
		BroadcastUserStatus(userId, false)
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
		case "private_message":
			HandlePrivateMessage(wsMsg.Content, userId)
		case "typing":
			// Handle typing indicators
			HandleTypingIndicator(wsMsg.Content, userId)
		case "read_receipt":
			// Handle read receipts
			HandleReadReceipt(wsMsg.Content, userId)
		default:
			log.Printf("Unknown message type: %s", wsMsg.Type)
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
	receiverId, ok := contentMap["receiver_id"].(string)
	if !ok {
		log.Printf("Invalid receiver ID")
		return
	}

	messageContent, ok := contentMap["content"].(string)
	if !ok {
		log.Printf("Invalid message content")
		return
	}

	// Get sender's username
	senderName, err := GetUsernameById(senderId)
	if err != nil {
		log.Printf("Error getting sender username: %v", err)
		return
	}

	// Create message struct
	now := time.Now()
	message := PrivateMessage{
		SenderId:   senderId,
		Sender:     senderName,
		ReceiverId: receiverId,
		Content:    messageContent,
		Timestamp:  now,
	}

	// Save message to database
	messageId, err := SaveMessage(message)
	if err != nil {
		log.Printf("Error saving message: %v", err)
		return
	}
	message.ID = messageId

	// Send message to recipient if online
	SendToUser(receiverId, "private_message", message)

	// Send confirmation back to sender
	SendToUser(senderId, "message_sent", map[string]interface{}{
		"messageId":  messageId,
		"receiverId": receiverId,
		"timestamp":  now,
	})
}

// HandleTypingIndicator processes typing indicators
func HandleTypingIndicator(content interface{}, senderId string) {
	contentMap, ok := content.(map[string]interface{})
	if !ok {
		return
	}

	receiverId, ok := contentMap["receiver_id"].(string)
	if !ok {
		return
	}

	isTyping, ok := contentMap["is_typing"].(bool)
	if !ok {
		return
	}

	// Send typing indicator to recipient
	SendToUser(receiverId, "typing_indicator", map[string]interface{}{
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

	messageId, ok := contentMap["message_id"].(float64)
	if !ok {
		return
	}

	otherUserId, ok := contentMap["user_id"].(string)
	if !ok {
		return
	}

	// Mark message as read in database
	err := MarkMessageAsRead(int64(messageId))
	if err != nil {
		log.Printf("Error marking message as read: %v", err)
	}

	// Notify sender that message was read
	SendToUser(otherUserId, "read_receipt", map[string]interface{}{
		"messageId": messageId,
		"userId":    userId,
	})
}

// SendToUser sends a message to a specific user
func SendToUser(userId string, messageType string, content interface{}) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	conn, exists := userConns[userId]
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
		delete(clients, conn)
		delete(userConns, userId)
	}
}

// BroadcastUserStatus notifies all users about a user's online status
func BroadcastUserStatus(userId string, isOnline bool) {
	message := WSMessage{
		Type: "user_status",
		Content: map[string]interface{}{
			"userId":   userId,
			"isOnline": isOnline,
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling status message: %v", err)
		return
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for client := range clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Error sending status message: %v", err)
			client.Close()
			uid := clients[client]
			delete(clients, client)
			delete(userConns, uid)
		}
	}
}

// BroadcastMessage sends a message to all connected clients (for forum events)
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
	log.Printf("Broadcasting to %d clients", len(clients))
	for client := range clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Error sending message: %v", err)
			client.Close()
			uid := clients[client]
			delete(clients, client)
			delete(userConns, uid)
		}
	}
	log.Printf("🔹 Remaining clients after cleanup: %d", len(clients))
	clientsMutex.Unlock()
}

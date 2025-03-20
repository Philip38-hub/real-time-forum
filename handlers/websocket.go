package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

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
	clients      = make(map[*websocket.Conn]bool)
	clientsMutex = sync.Mutex{}
)

// Message represents the structure of WebSocket messages
type WSMessage struct {
	Type    string      `json:"type"`    // "new_post", "new_comment", "new_like", etc.
	Content interface{} `json:"content"` // The actual data
}

// WebSocketHandler handles WebSocket connections
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		return
	}
	defer conn.Close()

	// Register the new client
	clientsMutex.Lock()
	clients[conn] = true
	log.Printf("Client connected! Total clients: %d", len(clients))
	clientsMutex.Unlock()

	// Remove client when connection closes
	defer func() {
		clientsMutex.Lock()
		delete(clients, conn)
		log.Printf("Client disconnected! Total clients: %d", len(clients))
		clientsMutex.Unlock()
	}()

	// Simple ping-pong to keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
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
	for client := range clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Error sending message: %v", err)
			client.Close()
			delete(clients, client)
		}
	}
	log.Printf("🔹 Remaining clients after cleanup: %d", len(clients))
	clientsMutex.Unlock()
}

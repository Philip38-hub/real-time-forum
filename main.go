package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"forum/handlers"
)

func main() {
	args := os.Args
	if len(args) != 1 {
		fmt.Println("usage: go run .")
		return
	}
	// Serve static files from the "static" directory
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	http.HandleFunc("/", handler)

	// Initialize the database and OAuth providers
	handlers.InitDB()
	handlers.InitGoogleOAuth()
	handlers.InitGithubOAuth()

	// Start the server
	log.Println("Server is running on http://localhost:8081")
	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)

	// Check if the request matches the "/api/messages" prefix
	if strings.HasPrefix(r.URL.Path, "/api/messages/") {
		// Get the part after "/api/messages/"
		remainingPath := strings.TrimPrefix(r.URL.Path, "/api/messages/")

		// Handle specific cases based on the remaining path
		switch remainingPath {
		case "send":
			handlers.SendMessageHandler(w, r)
		case "users":
			handlers.GetUsersHandler(w, r)
		case "mark-read":
			handlers.MarkMessageAsReadHandler(w, r)
		default:
			// Handle "/api/messages/{userId}" case
			handlers.GetMessagesHandler(w, r)
		}
		return
	}

	switch r.URL.Path {
	case "/":
		handlers.HomeHandler(w, r)
	case "/login":
		handlers.LoginHandler(w, r)
	case "/register":
		handlers.RegisterHandler(w, r)
	case "/like":
		handlers.LikeHandler(w, r)
	case "/filter":
		handlers.FilterHandler(w, r)
	case "/post":
		handlers.PostHandler(w, r)
	case "/comment":
		handlers.CommentHandler(w, r)
	case "/comment/like":
		handlers.CommentLikeHandler(w, r)
	case "/logout":
		handlers.LogoutHandler(w, r)
	case "/profile":
		handlers.ProfileHandler(w, r)
	case "/api/current-user":
		handlers.CurrentUserHandler(w, r)
	// WebSocket endpoint
	case "/ws":
		handlers.WebSocketHandler(w, r)
	// Google OAuth routes
	case "/auth/google/login":
		handlers.HandleGoogleLogin(w, r)
	case "/auth/google/callback":
		handlers.HandleGoogleCallback(w, r)
	// GitHub OAuth routes
	case "/auth/github/login":
		handlers.HandleGithubLogin(w, r)
	case "/auth/github/callback":
		handlers.HandleGithubCallback(w, r)
	// 	// Private messaging routes
	// case "/api/messages/":
	// 	handlers.GetMessagesHandler(w, r)
	// case "/api/messages/send":
	// 	handlers.SendMessageHandler(w, r)
	// case "/api/messages/users":
	// 	handlers.GetUsersHandler(w, r)
	// case "/api/messages/mark-read":
	// 	handlers.MarkMessageAsReadHandler(w, r)
	default:
		handlers.RenderError(w, r, "Page not found", http.StatusNotFound)
	}
}

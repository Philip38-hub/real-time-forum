package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"forum/handlers"
)

// Define valid frontend routes
var validFrontendRoutes = map[string]bool{
	"/":            true,
	"/login":       true,
	"/register":    true,
	"/profile":     true,
	"/post":        true,
	"/posts":       true,
	"/messages":    true,
	"/error":       true,
	"/create-post": true,
}

func main() {
	args := os.Args
	if len(args) != 1 {
		fmt.Println("usage: go run .")
		return
	}

	// Serve static files from the "static" directory
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
	// Serve static files and uploads
	if strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/uploads/") {
		http.ServeFile(w, r, r.URL.Path[1:]) // remove leading '/'
		return
	}

	// Check if the request matches the "/api/messages" prefix
	if strings.HasPrefix(r.URL.Path, "/api/messages/") {
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

	// API endpoints (only for correct methods)
	if isAPIEndpoint(r.URL.Path) {
		// Only handle /login as API for POST, otherwise serve SPA
		if (r.URL.Path == "/login" || r.URL.Path == "/register") && r.Method != http.MethodPost {
			if isValidFrontendRoute(r.URL.Path) {
				http.ServeFile(w, r, "static/index.html")
			} else {
				handlers.RenderError(w, r, "not_found", http.StatusNotFound)
			}
			return
		}
		handleAPI(w, r)
		return
	}

	// Check if it's a valid frontend route before serving the SPA
	if isValidFrontendRoute(r.URL.Path) {
		http.ServeFile(w, r, "static/index.html")
	} else {
		handlers.RenderError(w, r, "not_found", http.StatusNotFound)
	}
}

// isValidFrontendRoute checks if the given path is a registered frontend route
func isValidFrontendRoute(path string) bool {
	// Check if path is directly in our map
	if validFrontendRoutes[path] {
		return true
	}

	// Also check for paths with IDs (like /profile/123)
	for route := range validFrontendRoutes {
		if route != "/" && strings.HasPrefix(path, route+"/") {
			return true
		}
	}

	// Check for routes with query parameters
	// For example, /error?code=404 should match /error
	basePathEnd := strings.Index(path, "?")
	if basePathEnd != -1 {
		basePath := path[:basePathEnd]
		if validFrontendRoutes[basePath] {
			return true
		}
	}

	return false
}

func isAPIEndpoint(path string) bool {
	apiPaths := []string{
		"/api/posts",
		"/login",
		"/register",
		"/like",
		"/filter",
		"/post",
		"/comment",
		"/comment/like",
		"/logout",
		"/api/profile",
		"/api/current-user",
		"/ws",
		"/auth/google/login",
		"/auth/google/callback",
		"/auth/github/login",
		"/auth/github/callback",
	}

	// Check if the path matches any API endpoint
	for _, apiPath := range apiPaths {
		if strings.HasPrefix(path, apiPath) {
			return true
		}
	}

	return false
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/posts":
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
	case "/api/profile":
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
	default:
		handlers.RenderError(w, r, "not_found", http.StatusNotFound)
	}
}

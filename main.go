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

    // API endpoints (only for correct methods)
    if isAPIEndpoint(r.URL.Path) {
        // Only handle /login as API for POST, otherwise serve SPA
        if r.URL.Path == "/login" && r.Method != http.MethodPost {
            http.ServeFile(w, r, "static/index.html")
            return
        }
        handleAPI(w, r)
        return
    }

    // For all other routes, serve the SPA (index.html)
    http.ServeFile(w, r, "static/index.html")
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
    case "/profile":
        handlers.ProfileHandler(w, r)
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
        handlers.SendError(w, "Endpoint not found", http.StatusNotFound)
    }
}

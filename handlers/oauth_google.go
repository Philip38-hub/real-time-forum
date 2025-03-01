package handlers

import (
    "fmt"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/google/uuid"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    oauth2v2 "google.golang.org/api/oauth2/v2"
)
var (
	googleOauthConfig *oauth2.Config
	oauthStateString  string
)

// InitGoogleOAuth initializes the Google OAuth configuration
func InitGoogleOAuth() {
	// Get environment variables
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	// Print debug information
	fmt.Printf("\n=== Initializing Google OAuth ===\n")
	fmt.Printf("Client ID: %s\n", clientID[:10]+"..."+"(last 5 chars: "+clientID[len(clientID)-5:]+")")
	fmt.Printf("Client Secret: %s\n", clientSecret[:5]+"..."+"(last 5 chars: "+clientSecret[len(clientSecret)-5:]+")")
	fmt.Printf("Redirect URL: http://localhost:8081/auth/google/callback\n")

	// Verify required environment variables
	if clientID == "" || clientSecret == "" {
		fmt.Println("Error: GOOGLE_CLIENT_ID and/or GOOGLE_CLIENT_SECRET environment variables are not set")
		return
	}

	googleOauthConfig = &oauth2.Config{
	    ClientID:     clientID,
	    ClientSecret: clientSecret,
	    RedirectURL:  "http://localhost:8081/auth/google/callback",
	    Scopes: []string{
	        "openid",
	        "profile",
	        "email",
	        "https://www.googleapis.com/auth/userinfo.email",
	        "https://www.googleapis.com/auth/userinfo.profile",
	    },
	    Endpoint: google.Endpoint,
	}
	
	fmt.Printf("OAuth Configuration Details:\n")
	fmt.Printf("- Client ID: %s\n", clientID)
	fmt.Printf("- Redirect URL: %s\n", googleOauthConfig.RedirectURL)
	fmt.Printf("- Scopes: %s\n", strings.Join(googleOauthConfig.Scopes, ", "))
	fmt.Printf("- Endpoint Auth URL: %v\n", google.Endpoint.AuthURL)
	fmt.Printf("- Endpoint Token URL: %v\n", google.Endpoint.TokenURL)

	// Generate a random state string for CSRF protection
	oauthStateString = uuid.New().String()
	fmt.Printf("Generated OAuth state string: %s\n", oauthStateString)
}

// addSecurityHeaders adds necessary security headers to the response
func addSecurityHeaders(w http.ResponseWriter) {
    w.Header().Set("Content-Security-Policy",
        "default-src 'self' https://*.google.com https://accounts.google.com; "+
        "script-src 'self' 'unsafe-inline' https://*.google.com https://accounts.google.com; "+
        "frame-src https://*.google.com https://accounts.google.com; "+
        "img-src 'self' https: data:; "+
        "style-src 'self' 'unsafe-inline' https://*.google.com https://accounts.google.com https://cdnjs.cloudflare.com; "+
        "font-src 'self' https://cdnjs.cloudflare.com; "+
        "connect-src 'self' https://*.google.com https://accounts.google.com")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// HandleGoogleLogin handles the Google OAuth login/registration flow
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
    addSecurityHeaders(w)
    
    // Debug request information
    fmt.Printf("\n=== Google OAuth Request Details ===\n")
    fmt.Printf("Request URL: %s\n", r.URL.String())
    fmt.Printf("Request Method: %s\n", r.Method)
    fmt.Printf("Full Headers: %+v\n", r.Header)
    fmt.Printf("Referer Header: %s\n", r.Header.Get("Referer"))
    fmt.Printf("Raw Referer: %s\n", r.Referer())

    // Check if this is a registration or login flow
    isRegistration := false
    if referer := r.Header.Get("Referer"); referer != "" {
        isRegistration = strings.Contains(referer, "/register")
        fmt.Printf("Determined flow type from referer: %s (isRegistration=%v)\n", referer, isRegistration)
    } else {
        fmt.Printf("Warning: No referer header found, defaulting to login flow\n")
    }
    
    fmt.Printf("=== Starting Google OAuth %s Flow ===\n", map[bool]string{true: "Registration", false: "Login"}[isRegistration])

    if googleOauthConfig == nil {
        fmt.Println("Error: Google OAuth not configured properly")
        http.Error(w, "Google OAuth is not configured properly. Please try again later.", http.StatusInternalServerError)
        return
    }

    // Generate a simple state that includes the flow type
    stateUUID := uuid.New().String()
    state := fmt.Sprintf("%s:%v", stateUUID, isRegistration)
    
    // Store the state
    oauthStateString = state
    
    fmt.Printf("\nOAuth State Information:\n")
    fmt.Printf("State: %s\n", state)

    // Generate OAuth URL with the state
    url := googleOauthConfig.AuthCodeURL(state)
    fmt.Printf("\nGenerated OAuth URL:\n%s\n", url)
    fmt.Printf("\nState parameter breakdown:\n")
    fmt.Printf("- Full state: %s\n", state)
    fmt.Printf("- UUID part: %s\n", stateUUID)
    fmt.Printf("- Is Registration: %v\n", isRegistration)
    
    fmt.Printf("\nRedirecting to Google for %s...\n", map[bool]string{true: "registration", false: "login"}[isRegistration])
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleGoogleCallback handles the Google OAuth callback
func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    addSecurityHeaders(w)

    fmt.Printf("\n=== Google OAuth Callback Received ===\n")
    fmt.Printf("Full URL: %s\n", r.URL.String())
    fmt.Printf("Query Parameters: %+v\n", r.URL.Query())
    fmt.Printf("Headers: %+v\n", r.Header)
    fmt.Printf("Form Data: %+v\n", r.Form)
    fmt.Printf("Raw Query: %s\n", r.URL.RawQuery)

    // Parse form data to ensure we can access all parameters
    if err := r.ParseForm(); err != nil {
        fmt.Printf("Error parsing form data: %v\n", err)
        RenderError(w, r, "Error processing callback data", http.StatusBadRequest)
        return
    }

    // Set SameSite attribute for all cookies
    w.Header().Set("Set-Cookie", "SameSite=Lax")

    // Check if there's an error in the callback
	if errMsg := r.FormValue("error"); errMsg != "" {
	    errorReason := r.FormValue("error_reason")
	    errorDescription := r.FormValue("error_description")
	    
	    fmt.Printf("OAuth Error Details:\n")
	    fmt.Printf("- Error: %s\n", errMsg)
	    fmt.Printf("- Reason: %s\n", errorReason)
	    fmt.Printf("- Description: %s\n", errorDescription)
	    
	    errorMessage := fmt.Sprintf("Google sign-in error: %s. %s", errMsg, errorDescription)
	    RenderError(w, r, errorMessage, http.StatusUnauthorized)
	    return
	}

	if googleOauthConfig == nil {
	    fmt.Println("Error: Google OAuth configuration is nil in callback")
	    RenderError(w, r, "Google OAuth configuration error", http.StatusInternalServerError)
	    return
	}
	
	// Verify state parameter
	stateParam := r.FormValue("state")
	fmt.Printf("\n=== Processing OAuth Callback ===\n")
	fmt.Printf("Received state: %s\n", stateParam)
	fmt.Printf("Stored state: %s\n", oauthStateString)

	if stateParam != oauthStateString {
	    fmt.Printf("State mismatch!\n")
	    fmt.Printf("Received: %s\n", stateParam)
	    fmt.Printf("Expected: %s\n", oauthStateString)
	    RenderError(w, r, "Invalid authentication state. Please try again.", http.StatusBadRequest)
	    return
	}

	// Parse state parameter (format: "uuid:isRegister")
	stateParts := strings.Split(stateParam, ":")
	if len(stateParts) != 2 {
	    fmt.Printf("Invalid state format: %s\n", stateParam)
	    RenderError(w, r, "Invalid authentication state.", http.StatusBadRequest)
	    return
	}

	// Extract flow type
	isRegister := stateParts[1] == "true"
	fmt.Printf("Flow type from state: %s\n", map[bool]string{true: "Registration", false: "Login"}[isRegister])
	fmt.Printf("Processing %s flow\n", map[bool]string{true: "registration", false: "login"}[isRegister])

	// Exchange auth code for token
	code := r.FormValue("code")
	if code == "" {
		fmt.Println("No code received from Google")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Println("Attempting to exchange code for token...")
	token, err := googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		fmt.Printf("Code exchange failed: %s\n", err.Error())
		fmt.Printf("Full error details: %+v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Println("Successfully obtained token from Google")

	// Get user info from Google
	fmt.Println("Creating OAuth2 client...")
	client := googleOauthConfig.Client(r.Context(), token)
	fmt.Println("Creating OAuth2 service...")
	service, err := oauth2v2.New(client)
	if err != nil {
		fmt.Printf("Failed to create OAuth2 service: %v\n", err)
		fmt.Printf("Full error details: %+v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Println("Fetching user info from Google...")
	userInfo, err := service.Userinfo.Get().Do()
	if err != nil {
		fmt.Printf("Failed to get user info: %v\n", err)
		fmt.Printf("Full error details: %+v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Printf("Successfully retrieved user info: Email=%s, Name=%s\n", userInfo.Email, userInfo.Name)

	// Check if user exists (by email or Google ID)
	fmt.Printf("Checking if user exists with Email: %s or Google ID: %s\n", userInfo.Email, userInfo.Id)
	var userID string
	err = db.QueryRow("SELECT id FROM users WHERE email = ? OR google_id = ?", userInfo.Email, userInfo.Id).Scan(&userID)
	if err != nil {
	    if isRegister {
	        // Create new user for registration
	        fmt.Println("Creating new user through registration...")
	        userID = uuid.New().String()
	        _, err = db.Exec(`
	            INSERT INTO users (id, email, username, google_id, avatar_url)
	            VALUES (?, ?, ?, ?, ?)`,
	            userID, userInfo.Email, userInfo.Name, userInfo.Id, userInfo.Picture)
	        if err != nil {
	            fmt.Printf("Failed to create user: %v\n", err)
	            fmt.Printf("Insert query details: id=%s, email=%s, name=%s, google_id=%s\n",
	                userID, userInfo.Email, userInfo.Name, userInfo.Id)
	            RenderError(w, r, "Failed to complete registration. Please try again.", http.StatusInternalServerError)
	            return
	        }
	        fmt.Printf("Successfully registered new user with ID: %s\n", userID)
	    } else {
	        // User doesn't exist and trying to login
	        fmt.Printf("Login attempt for non-existent account\n")
	        RenderError(w, r, "No account found with this email. Please register first.", http.StatusUnauthorized)
	        return
	    }
	} else {
	    // User exists
	    if isRegister {
	        // Check if the account has a Google ID
	        var existingGoogleID string
	        err = db.QueryRow("SELECT google_id FROM users WHERE id = ?", userID).Scan(&existingGoogleID)
	        if err == nil && existingGoogleID != "" {
	            fmt.Printf("Registration attempt for existing Google account\n")
	            RenderError(w, r, "An account with this Google ID already exists. Please login instead.", http.StatusConflict)
	            return
	        }
	        
	        // Update existing account with Google ID
	        _, err = db.Exec("UPDATE users SET google_id = ? WHERE id = ?", userInfo.Id, userID)
	        if err != nil {
	            fmt.Printf("Failed to link Google account: %v\n", err)
	            RenderError(w, r, "Failed to link Google account. Please try again.", http.StatusInternalServerError)
	            return
	        }
	        fmt.Printf("Successfully linked Google account for user ID: %s\n", userID)
	        w.Header().Set("X-Auth-Message", fmt.Sprintf("Your Google account has been linked successfully! Welcome, %s!", userInfo.Name))
	    } else {
	        fmt.Printf("Successfully logged in existing user with ID: %s\n", userID)
	        w.Header().Set("X-Auth-Message", fmt.Sprintf("Welcome back, %s!", userInfo.Name))
	    }
	}

	// Store tokens
	fmt.Println("Storing Google OAuth tokens in database...")
	expiresAt := time.Now().Add(time.Second * time.Duration(token.Expiry.Unix()-time.Now().Unix()))
	fmt.Printf("Token expiry set to: %v\n", expiresAt)

	_, err = db.Exec(`
	INSERT OR REPLACE INTO google_auth (user_id, access_token, refresh_token, expires_at)
	VALUES (?, ?, ?, ?)`,
	userID, token.AccessToken, token.RefreshToken, expiresAt)
	if err != nil {
	fmt.Printf("Failed to store token: %v\n", err)
	fmt.Printf("Token storage details - User ID: %s, Expires At: %v\n", userID, expiresAt)
	RenderError(w, r, "Failed to complete authentication. Please try signing in again.", http.StatusInternalServerError)
	return
	}
	fmt.Println("Successfully stored Google OAuth tokens")

	// Create session
	fmt.Println("Creating new session...")
	sessionID := uuid.New().String()
	fmt.Printf("Generated session ID: %s for user ID: %s\n", sessionID, userID)

	_, err = db.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, userID)
	if err != nil {
		fmt.Printf("Failed to create session: %v\n", err)
		fmt.Printf("Session creation details - Session ID: %s, User ID: %s\n", sessionID, userID)
		RenderError(w, r, "Failed to create session. Please try signing in again.", http.StatusInternalServerError)
		return
	}
	fmt.Println("Successfully created session in database")

	// Set session cookie
	fmt.Println("Setting session cookie...")
	cookieExpiry := time.Now().Add(24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  cookieExpiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	fmt.Printf("Set session cookie with expiry: %v\n", cookieExpiry)

	// Log success message based on flow type
	if isRegister {
	    fmt.Printf("Google account setup completed! User: %s (%s)\n", userInfo.Name, userInfo.Email)
	    w.Header().Set("X-Auth-Message", fmt.Sprintf("Welcome to our community, %s!", userInfo.Name))
	} else {
	    fmt.Printf("Google login successful! User: %s (%s)\n", userInfo.Name, userInfo.Email)
	    w.Header().Set("X-Auth-Message", fmt.Sprintf("Welcome back, %s!", userInfo.Name))
	}
	
	// Redirect to home page with appropriate status
	fmt.Println("Redirecting to home page...")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

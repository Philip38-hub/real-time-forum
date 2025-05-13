package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ErrorData represents the data passed to the error template
type ErrorData struct {
	StatusCode   int
	ErrorMessage string
	HelpMessage  string
	IsLoggedIn   bool
}

// Common error messages and help text
var (
	ErrorMessages = map[string]ErrorData{
		// Authentication errors
		"invalid_credentials": {
			StatusCode:   http.StatusUnauthorized,
			ErrorMessage: "Invalid email or password",
			HelpMessage:  "Please check your email and password and try again. If you've forgotten your password, you can reset it.",
		},
		"unauthorized": {
			StatusCode:   http.StatusUnauthorized,
			ErrorMessage: "You must be logged in to perform this action",
			HelpMessage:  "Please log in to your account to continue.",
		},
		"invalid_session": {
			StatusCode:   http.StatusUnauthorized,
			ErrorMessage: "Your session has expired",
			HelpMessage:  "Please log in again to continue.",
		},

		// Method errors
		"method_not_allowed": {
			StatusCode:   http.StatusMethodNotAllowed,
			ErrorMessage: "Method not allowed",
			HelpMessage:  "This action can only be performed with a specific HTTP method.",
		},

		// Registration errors
		"invalid_email": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Invalid email format",
			HelpMessage:  "Please enter a valid email address (e.g., user@example.com).",
		},
		"email_exists": {
			StatusCode:   http.StatusConflict,
			ErrorMessage: "Email already registered",
			HelpMessage:  "This email is already registered. Please use a different email or try logging in.",
		},
		"password_too_short": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Password is too short",
			HelpMessage:  "Password must be at least 8 characters long. Use a mix of letters, numbers, and symbols for better security.",
		},
		"invalid_username_format": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Invalid username format",
			HelpMessage:  "Username must start with a letter, contain only letters, numbers, underscores, periods, and hyphens, and be between 3-30 characters.",
		},
		"username_contains_at": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Username cannot contain @ symbol",
			HelpMessage:  "Please choose a username without the @ symbol.",
		},
		"reserved_username": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "This username is reserved",
			HelpMessage:  "This username is reserved and cannot be used. Please choose a different username.",
		},
		"username_taken": {
			StatusCode:   http.StatusConflict,
			ErrorMessage: "Username already taken",
			HelpMessage:  "This username is already taken. Please choose a different username.",
		},
		"age_restriction": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Age restriction",
			HelpMessage:  "You must be at least 13 years old to register.",
		},
		"invalid_gender": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Invalid gender selection",
			HelpMessage:  "Please select a valid gender option.",
		},

		// Input validation errors
		"invalid_input": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Invalid input provided",
			HelpMessage:  "Please check your input and try again. All required fields must be filled out.",
		},
		"missing_fields": {
			StatusCode:   http.StatusBadRequest,
			ErrorMessage: "Required fields are missing",
			HelpMessage:  "Please fill out all required fields marked with an asterisk (*).",
		},

		// Not found errors
		"not_found": {
			StatusCode:   http.StatusNotFound,
			ErrorMessage: "Page not found",
			HelpMessage:  "The page you are looking for might have been removed or is temporarily unavailable.",
		},
		"post_not_found": {
			StatusCode:   http.StatusNotFound,
			ErrorMessage: "Post not found",
			HelpMessage:  "The post you're looking for might have been deleted or never existed.",
		},
		"comment_not_found": {
			StatusCode:   http.StatusNotFound,
			ErrorMessage: "Comment not found",
			HelpMessage:  "The comment you're looking for might have been deleted or never existed.",
		},

		// Server errors
		"database_error": {
			StatusCode:   http.StatusInternalServerError,
			ErrorMessage: "Database error occurred",
			HelpMessage:  "We're experiencing technical difficulties. Please try again later.",
		},
		"server_error": {
			StatusCode:   http.StatusInternalServerError,
			ErrorMessage: "Internal server error",
			HelpMessage:  "Something went wrong on our end. Please try again later.",
		},

		// Permission errors
		"forbidden": {
			StatusCode:   http.StatusForbidden,
			ErrorMessage: "Access denied",
			HelpMessage:  "You don't have permission to perform this action.",
		},
		"not_owner": {
			StatusCode:   http.StatusForbidden,
			ErrorMessage: "Not the owner",
			HelpMessage:  "You can only modify content that you created.",
		},
	}
)

// RenderErrorFunc is the type for rendering error responses
type RenderErrorFunc func(w http.ResponseWriter, r *http.Request, errorKey string, statusCode int)

// RenderError renders an error response
func renderError(w http.ResponseWriter, r *http.Request, errorKey string, statusCode int) {
	// Get user's login status
	userID := GetUserIdFromSession(w, r)
	isLoggedIn := userID != ""

	// Get error data from the map, or use default if not found
	errorData, exists := ErrorMessages[errorKey]
	if !exists {
		// If the error key doesn't exist, create a generic error with the key as the message
		errorData = ErrorData{
			StatusCode:   statusCode,
			ErrorMessage: errorKey, // Use the error key as the message
			HelpMessage:  "Please try again or contact support if the problem persists.",
		}
	}
	errorData.IsLoggedIn = isLoggedIn

	// Check if this is an API request or a browser request
	isAPIRequest := r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		r.Header.Get("Accept") == "application/json"

	// For API requests, return JSON
	if isAPIRequest {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(errorData.StatusCode)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     false,
			"error":       errorData.ErrorMessage,
			"helpMessage": errorData.HelpMessage,
			"statusCode":  errorData.StatusCode,
			"isLoggedIn":  errorData.IsLoggedIn,
		})
		return
	}

	redirectURL := fmt.Sprintf("/error?code=%d&message=%s&help=%s",
		errorData.StatusCode,
		url.QueryEscape(errorData.ErrorMessage),
		url.QueryEscape(errorData.HelpMessage))

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// RenderError is a function variable that can be mocked in tests
var RenderError RenderErrorFunc = renderError

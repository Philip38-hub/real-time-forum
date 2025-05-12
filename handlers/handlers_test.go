package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

var parseTemplate = func(_ ...string) (*template.Template, error) {
	return template.New("mock").Parse("<html></html>") // Mock template
}

func TestHomeHandler(t *testing.T) {
	// Store original functions to restore after test
	originalGetUserIdFromSession := GetUserIdFromSession
	originalGetCommentsForPost := GetCommentsForPost
	originalDB := db
	originalRenderError := RenderError

	// Restore original functions after test
	defer func() {
		GetUserIdFromSession = originalGetUserIdFromSession
		GetCommentsForPost = originalGetCommentsForPost
		db = originalDB
		RenderError = originalRenderError
	}()

	// Test case: Database Query Error
	t.Run("Database Query Error", func(t *testing.T) {
		// Mock GetUserIdFromSession
		GetUserIdFromSession = func(w http.ResponseWriter, r *http.Request) string {
			return "testuser"
		}

		// Create a mock database that will cause a query error
		mockDB, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			t.Fatalf("Failed to create mock database: %v", err)
		}
		defer mockDB.Close()

		// Replace global db with mock
		db = mockDB

		// Track if RenderError was called
		var renderErrorCalled bool
		RenderError = func(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
			renderErrorCalled = true
			http.Error(w, message, statusCode)
		}

		// Create request and response recorder
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		// Call handler
		HomeHandler(w, req)

		// Check if RenderError was called
		if !renderErrorCalled {
			t.Errorf("Expected RenderError to be called on database query error")
		}
	})
}

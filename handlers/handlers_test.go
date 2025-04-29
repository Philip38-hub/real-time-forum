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

func TestGetCommentsForPost(t *testing.T) {
	// Setup mock database
	mockDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer mockDB.Close()

	// Replace global db with mock
	originalDB := db
	db = mockDB
	defer func() { db = originalDB }()

	// Prepare mock database schema and data
	_, err = mockDB.Exec(`
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            nickname TEXT
        );
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            title TEXT
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER,
            user_id TEXT,
            content TEXT,
            created_at DATETIME,
            parent_id INTEGER,
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(parent_id) REFERENCES comments(id)
        );
        CREATE TABLE comment_likes (
            comment_id INTEGER,
            user_id TEXT,
            is_like BOOLEAN,
            FOREIGN KEY(comment_id) REFERENCES comments(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- Insert test users
        INSERT INTO users (id, nickname) VALUES 
        ('user1', 'testuser1'),
        ('user2', 'testuser2');

        -- Insert test post
        INSERT INTO posts (id, title) VALUES (1, 'Test Post');

        -- Insert test comments
        INSERT INTO comments (id, post_id, user_id, content, created_at, parent_id) VALUES 
        (1, 1, 'user1', 'First comment', '2024-01-01 10:00:00', NULL),
        (2, 1, 'user2', 'Second comment', '2024-01-01 11:00:00', NULL),
        (3, 1, 'user1', 'Reply to first', '2024-01-01 12:00:00', 1);

        -- Insert comment likes
        INSERT INTO comment_likes (comment_id, user_id, is_like) VALUES 
        (1, 'user1', 1),
        (1, 'user2', 1),
        (2, 'user1', 0),
        (2, 'user2', 0);
    `)
	if err != nil {
		t.Fatalf("Failed to prepare mock data: %v", err)
	}

	// Mock GetCommentReplies
	originalGetCommentReplies := GetCommentReplies
	GetCommentReplies = func(commentID int, userID string) ([]Comment, error) {
		if commentID == 1 {
			return []Comment{
				{
					ID:       3,
					PostID:   1,
					UserID:   "user1",
					Content:  "Reply to first",
					Nickname: "testuser1",
				},
			}, nil
		}
		return []Comment{}, nil
	}
	defer func() { GetCommentReplies = originalGetCommentReplies }()

	// Test cases
	tests := []struct {
		name     string
		postID   int
		userID   string
		wantErr  bool
		wantLen  int
		wantLike bool
	}{
		{
			name:     "Valid post with logged in user",
			postID:   1,
			userID:   "user1",
			wantErr:  false,
			wantLen:  2,
			wantLike: true,
		},
		{
			name:     "Valid post without user",
			postID:   1,
			userID:   "",
			wantErr:  false,
			wantLen:  2,
			wantLike: false,
		},
		{
			name:    "Non-existent post",
			postID:  999,
			userID:  "user1",
			wantErr: false,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comments, err := GetCommentsForPost(tt.postID, tt.userID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetCommentsForPost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(comments) != tt.wantLen {
				t.Errorf("GetCommentsForPost() got %v comments, want %v", len(comments), tt.wantLen)
			}

			if len(comments) > 0 && tt.userID != "" {
				if comments[0].UserLiked != tt.wantLike {
					t.Errorf("GetCommentsForPost() first comment UserLiked = %v, want %v",
						comments[0].UserLiked, tt.wantLike)
				}
			}
		})
	}
}

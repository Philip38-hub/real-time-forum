package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

// CommentLikeResponse is the response for like/dislike actions
type CommentLikeResponse struct {
	LikeCount    int   `json:"likeCount"`
	DislikeCount int   `json:"dislikeCount"`
	UserLiked    *bool `json:"userLiked"`
}

// CommentLikeHandler handles liking/disliking comments
func CommentLikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		RenderError(w, r, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user ID from session
	userID := GetUserIdFromSession(w, r)
	if userID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse comment ID and like status from request
	commentID := r.FormValue("comment_id")
	isLike := r.FormValue("is_like")

	if commentID == "" {
		RenderError(w, r, "missing_fields", http.StatusBadRequest)
		return
	}

	commentIDInt, err := strconv.Atoi(commentID)
	if err != nil {
		RenderError(w, r, "invalid_input", http.StatusBadRequest)
		return
	}

	// Verify comment exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM comments WHERE id = ?)", commentIDInt).Scan(&exists)
	if err != nil {
		log.Printf("Error checking comment existence: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}
	if !exists {
		RenderError(w, r, "not_found", http.StatusNotFound)
		return
	}

	isLikeBool := isLike == "true"

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}
	defer tx.Rollback()

	// Check if user has already liked/disliked this comment
	var existingIsLike sql.NullBool
	err = tx.QueryRow(
		"SELECT is_like FROM comment_likes WHERE comment_id = ? AND user_id = ?",
		commentIDInt, userID,
	).Scan(&existingIsLike)

	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error checking existing like: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}

	if existingIsLike.Valid {
		if existingIsLike.Bool == isLikeBool {
			// Remove the like/dislike if clicking the same button
			_, err = tx.Exec("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?",
				commentIDInt, userID)
		} else {
			// Update from like to dislike or vice versa
			_, err = tx.Exec("UPDATE comment_likes SET is_like = ? WHERE comment_id = ? AND user_id = ?",
				isLikeBool, commentIDInt, userID)
		}
	} else {
		// Add new like/dislike
		_, err = tx.Exec("INSERT INTO comment_likes (comment_id, user_id, is_like) VALUES (?, ?, ?)",
			commentIDInt, userID, isLikeBool)
	}

	if err != nil {
		log.Printf("Error updating like status: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}

	// Get updated counts and user's current like status
	var response CommentLikeResponse
	var userLiked sql.NullBool
	err = tx.QueryRow(`
		SELECT 
			(SELECT COUNT(*) FROM comment_likes WHERE comment_id = ? AND is_like = 1),
			(SELECT COUNT(*) FROM comment_likes WHERE comment_id = ? AND is_like = 0),
			CASE 
				WHEN EXISTS (SELECT 1 FROM comment_likes WHERE comment_id = ? AND user_id = ?)
				THEN (SELECT is_like FROM comment_likes WHERE comment_id = ? AND user_id = ?)
				ELSE NULL 
			END
	`, commentIDInt, commentIDInt, commentIDInt, userID, commentIDInt, userID).Scan(&response.LikeCount, &response.DislikeCount, &userLiked)
	if err != nil {
		log.Printf("Error getting updated counts: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}

	if userLiked.Valid {
		response.UserLiked = &userLiked.Bool
	} else {
		response.UserLiked = nil
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		HandleDatabaseError(w, r, err)
		return
	}

	// Return response as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		RenderError(w, r, "server_error", http.StatusInternalServerError)
		return
	}
}

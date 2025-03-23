package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

// CommentLikeHandler handles liking/disliking comments
func CommentLikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if the user is logged in
	session, err := r.Cookie("session_id")
	if err != nil {
		// User is not logged in, return a custom JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  false,
			"error":    "You must be logged in to like a comment",
			"redirect": "/login", // Add a redirect URL
		})
		return
	}

	// Get the user ID from the session
	var userID string
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", session.Value).Scan(&userID)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Parse the form data
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Parse comment ID and like status from request
	commentID := r.FormValue("comment_id")
	isLike, err := strconv.ParseBool(r.FormValue("is_like"))
	if err != nil {
		http.Error(w, "Invalid like/dislike value", http.StatusBadRequest)
		return
	}

	if commentID == "" {
		http.Error(w, "Comment ID is required", http.StatusBadRequest)
		return
	}

	commentIDInt, err := strconv.Atoi(commentID)
	if err != nil {
		http.Error(w, "Invalid comment ID", http.StatusBadRequest)
		return
	}

	// Verify comment exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM comments WHERE id = ?)", commentIDInt).Scan(&exists)
	if err != nil {
		log.Printf("Error checking comment existence: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Comment not found", http.StatusNotFound)
		return
	}

	// Check if the user has already liked/disliked the comment
	var existingIsLike bool
	err = db.QueryRow("SELECT is_like FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentIDInt, userID).Scan(&existingIsLike)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// If the user is trying to toggle their like/dislike
	if err != sql.ErrNoRows {
		if existingIsLike == isLike {
			// User is trying to remove their like/dislike
			_, err = db.Exec("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentIDInt, userID)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		} else {
			// User is changing their like/dislike
			_, err = db.Exec("UPDATE comment_likes SET is_like = ? WHERE comment_id = ? AND user_id = ?", isLike, commentIDInt, userID)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		}
	} else {
		// User is adding a new like/dislike
		_, err = db.Exec("INSERT INTO comment_likes (comment_id, user_id, is_like) VALUES (?, ?, ?)", commentIDInt, userID, isLike)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	// Get the updated like and dislike counts
	var likeCount, dislikeCount int
	err = db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE comment_id = ? AND is_like = 1", commentIDInt).Scan(&likeCount)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	err = db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE comment_id = ? AND is_like = 0", commentIDInt).Scan(&dislikeCount)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check if the user has liked/disliked the comment
	var userLiked sql.NullBool
	err = db.QueryRow("SELECT is_like FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentIDInt, userID).Scan(&userLiked)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Construct the reaction data to send
	reactionData := map[string]interface{}{
		"target_id":     commentIDInt,
		"target_type":   "comment",
		"like_count":    likeCount,
		"dislike_count": dislikeCount,
		"user_liked":    userLiked.Bool, // Whether the user has liked this comment
	}

	// Broadcast the reaction update to all connected clients
	BroadcastMessage("commentLikeUpdate", reactionData)

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"reactions": reactionData,
	})
}

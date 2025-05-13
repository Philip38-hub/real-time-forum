package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type LikeResponse struct {
	Success      bool `json:"success"`
	LikeCount    int  `json:"like_count"`
	DislikeCount int  `json:"dislike_count"`
}

func LikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		RenderError(w, r, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if the user is logged in
	session, err := r.Cookie("session_id")
	if err != nil {
		// User is not logged in
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the user ID from the session
	var userID string
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", session.Value).Scan(&userID)
	if err != nil {
		RenderError(w, r, "invalid_session", http.StatusUnauthorized)
		return
	}

	// Parse the form data
	err = r.ParseForm()
	if err != nil {
		RenderError(w, r, "invalid_input", http.StatusBadRequest)
		return
	}

	postID := r.FormValue("post_id")
	isLike, err := strconv.ParseBool(r.FormValue("is_like"))
	if err != nil {
		RenderError(w, r, "invalid_input", http.StatusBadRequest)
		return
	}

	// Check if the user has already liked/disliked the post
	var existingIsLike bool
	err = db.QueryRow("SELECT is_like FROM likes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingIsLike)
	if err != nil && err != sql.ErrNoRows {
		HandleDatabaseError(w, r, err)
		return
	}

	// If the user is trying to toggle their like/dislike
	if err != sql.ErrNoRows {
		if existingIsLike == isLike {
			// User is trying to remove their like/dislike
			_, err = db.Exec("DELETE FROM likes WHERE post_id = ? AND user_id = ?", postID, userID)
			if err != nil {
				HandleDatabaseError(w, r, err)
				return
			}
		} else {
			// User is changing their like/dislike
			_, err = db.Exec("UPDATE likes SET is_like = ? WHERE post_id = ? AND user_id = ?", isLike, postID, userID)
			if err != nil {
				HandleDatabaseError(w, r, err)
				return
			}
		}
	} else {
		// User is adding a new like/dislike
		_, err = db.Exec("INSERT INTO likes (post_id, user_id, is_like) VALUES (?, ?, ?)", postID, userID, isLike)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				RenderError(w, r, "invalid_input", http.StatusBadRequest)
				return
			}
			HandleDatabaseError(w, r, err)
			return
		}
	}

	// Get the updated like and dislike counts
	var likeCount, dislikeCount int
	err = db.QueryRow("SELECT COUNT(*) FROM likes WHERE post_id = ? AND is_like = 1", postID).Scan(&likeCount)
	if err != nil {
		HandleDatabaseError(w, r, err)
		return
	}
	err = db.QueryRow("SELECT COUNT(*) FROM likes WHERE post_id = ? AND is_like = 0", postID).Scan(&dislikeCount)
	if err != nil {
		HandleDatabaseError(w, r, err)
		return
	}

	// Return the updated counts
	response := LikeResponse{
		Success:      true,
		LikeCount:    likeCount,
		DislikeCount: dislikeCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

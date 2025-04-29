package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

var PostID int

// CommentHandler now returns JSON instead of redirecting
func CommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	postID := r.FormValue("post_id")
	postIDInt, err := strconv.Atoi(postID)
	if err != nil {
		SendError(w, "Invalid post ID format", http.StatusBadRequest)
		return
	} else {
		PostID = postIDInt
	}
	content := r.FormValue("content")
	parentID := r.FormValue("parent_id")
	userID := GetUserIdFromSession(w, r)

	if userID == "" {
		SendError(w, "Please log in to comment on posts", http.StatusUnauthorized)
		return
	}

	if postID == "" {
		SendError(w, "Post ID is required", http.StatusBadRequest)
		return
	}

	if content == "" {
		SendError(w, "Comment content cannot be empty", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		SendError(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var result sql.Result
	if parentID != "" {
		parentIDInt, err := strconv.Atoi(parentID)
		if err != nil {
			SendError(w, "Invalid parent comment ID format", http.StatusBadRequest)
			return
		}

		var parentPostID int
		err = db.QueryRow("SELECT post_id FROM comments WHERE id = ?", parentIDInt).Scan(&parentPostID)
		if err == sql.ErrNoRows {
			SendError(w, "Parent comment not found", http.StatusNotFound)
			return
		} else if err != nil {
			SendError(w, "Database error", http.StatusInternalServerError)
			return
		}

		result, err = tx.Exec(
			"INSERT INTO comments (post_id, user_id, content, parent_id, created_at) VALUES (?, ?, ?, ?, ?)",
			postIDInt, userID, content, parentIDInt, time.Now(),
		)
		if err != nil {
			SendError(w, "Failed to insert comment", http.StatusInternalServerError)
			return
		}

	} else {
		result, err = tx.Exec(
			"INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
			postIDInt, userID, content, time.Now(),
		)
	}

	if err != nil {
		SendError(w, "Failed to insert comment", http.StatusInternalServerError)
		return
	}

	if err = tx.Commit(); err != nil {
		SendError(w, "Error committing transaction", http.StatusInternalServerError)
		return
	}

	// Get the newly created comment's ID
	commentID, _ := result.LastInsertId()

	// Fetch the complete comment data to return
	comment, err := GetCommentByID(int(commentID), userID)
	if err != nil {
		SendError(w, "Error fetching new comment", http.StatusInternalServerError)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"comment": comment,
	})
}

// GetCommentsForPost fetches comments with user-specific like information
var GetCommentsForPost = func(postID int, userID string) ([]Comment, error) {
	rows, err := db.Query(`
        SELECT 
            c.id, 
            c.post_id,
            c.user_id,
            c.content,
            c.created_at,
            u.nickname,
            c.parent_id,
            (SELECT COUNT(*) FROM comments r WHERE r.parent_id = c.id) as reply_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 1) as like_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 0) as dislike_count,
            CASE WHEN ul.is_like = 1 THEN true WHEN ul.is_like = 0 THEN false ELSE false END as user_liked,
            CASE WHEN ul.is_like = 0 THEN true ELSE false END as user_disliked
        FROM comments c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN comment_likes ul ON c.id = ul.comment_id AND ul.user_id = ?
        WHERE c.post_id = ? AND c.parent_id IS NULL
        ORDER BY c.created_at DESC
    `, userID, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		err := rows.Scan(
			&comment.ID,
			&comment.PostID,
			&comment.UserID,
			&comment.Content,
			&comment.CreatedAt,
			&comment.Username,
			&comment.ParentID,
			&comment.ReplyCount,
			&comment.LikeCount,
			&comment.DislikeCount,
			&comment.UserLiked,
			&comment.UserDisliked,
		)
		if err != nil {
			return nil, err
		}

		replies, err := GetCommentReplies(comment.ID, userID)
		if err != nil {
			return nil, err
		}
		comment.Replies = replies

		comments = append(comments, comment)
	}

	return comments, nil
}

// GetCommentReplies fetches replies with user-specific like information
var GetCommentReplies = func(commentID int, userID string) ([]Comment, error) {
	rows, err := db.Query(`
        SELECT 
            c.id, 
            c.post_id,
            c.user_id,
            c.content,
            c.created_at,
            u.nickname,
            c.parent_id,
            0 as reply_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 1) as like_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 0) as dislike_count,
            CASE WHEN ul.is_like = 1 THEN true WHEN ul.is_like = 0 THEN false ELSE false END as user_liked,
            CASE WHEN ul.is_like = 0 THEN true ELSE false END as user_disliked
        FROM comments c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN comment_likes ul ON c.id = ul.comment_id AND ul.user_id = ?
        WHERE c.parent_id = ?
        ORDER BY c.created_at ASC
    `, userID, commentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var replies []Comment
	for rows.Next() {
		var reply Comment
		err := rows.Scan(
			&reply.ID,
			&reply.PostID,
			&reply.UserID,
			&reply.Content,
			&reply.CreatedAt,
			&reply.Username,
			&reply.ParentID,
			&reply.ReplyCount,
			&reply.LikeCount,
			&reply.DislikeCount,
			&reply.UserLiked,
			&reply.UserDisliked,
		)
		if err != nil {
			return nil, err
		}
		replies = append(replies, reply)
	}

	return replies, nil
}

// GetCommentByID fetches a single comment with all its data
func GetCommentByID(commentID int, userID string) (Comment, error) {
	var comment Comment
	err := db.QueryRow(`
        SELECT 
            c.id, 
            c.post_id,
            c.user_id,
            c.content,
            c.created_at,
            u.nickname,
            c.parent_id,
            (SELECT COUNT(*) FROM comments r WHERE r.parent_id = c.id) as reply_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 1) as like_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.is_like = 0) as dislike_count,
            CASE WHEN ul.is_like = 1 THEN true WHEN ul.is_like = 0 THEN false ELSE false END as user_liked,
            CASE WHEN ul.is_like = 0 THEN true ELSE false END as user_disliked
        FROM comments c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN comment_likes ul ON c.id = ul.comment_id AND ul.user_id = ?
        WHERE c.id = ?
    `, userID, commentID).Scan(
		&comment.ID,
		&comment.PostID,
		&comment.UserID,
		&comment.Content,
		&comment.CreatedAt,
		&comment.Username,
		&comment.ParentID,
		&comment.ReplyCount,
		&comment.LikeCount,
		&comment.DislikeCount,
		&comment.UserLiked,
		&comment.UserDisliked,
	)
	return comment, err
}

// GetUserIdFromSession retrieves the user ID from the session
var GetUserIdFromSession = func(w http.ResponseWriter, r *http.Request) string {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}

	var userID string
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionCookie.Value).Scan(&userID)
	if err == sql.ErrNoRows {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
		return ""
	} else if err != nil {
		return ""
	}

	return userID
}

// GetPostByID fetches a single post by ID
func GetPostByID(id string) (Post, error) {
	var post Post
	err := db.QueryRow("SELECT id, title, content FROM posts WHERE id = ?", id).Scan(&post.ID, &post.Title, &post.Content)
	return post, err
}

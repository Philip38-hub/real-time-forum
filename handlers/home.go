package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIdFromSession(w, r)

	// Query to fetch all posts along with user info, categories, like counts, and user-specific like status
	query := `
		SELECT 
			p.id, p.title, p.content, p.image_path, 
			GROUP_CONCAT(pc.category) as categories,
			u.username, p.created_at,
			COALESCE(l.like_count, 0) AS like_count,
			COALESCE(l.dislike_count, 0) AS dislike_count,
			CASE WHEN ul.is_like = 1 THEN true WHEN ul.is_like = 0 THEN false ELSE null END as user_liked,
			CASE WHEN ul.is_like = 0 THEN true ELSE false END as user_disliked
		FROM posts p
		JOIN users u ON p.user_id = u.id
		LEFT JOIN post_categories pc ON p.id = pc.post_id
		LEFT JOIN (
			SELECT post_id,
			COUNT(CASE WHEN is_like = 1 THEN 1 END) AS like_count,
			COUNT(CASE WHEN is_like = 0 THEN 1 END) AS dislike_count
			FROM likes
			GROUP BY post_id
		) l ON p.id = l.post_id
		LEFT JOIN likes ul ON p.id = ul.post_id AND ul.user_id = ?
		GROUP BY p.id, p.title, p.content, u.username, p.created_at
		ORDER BY p.created_at DESC`

	rows, err := db.Query(query, userID)
	if err != nil {
		SendError(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		var categories sql.NullString
		var userLiked, userDisliked sql.NullBool
		err := rows.Scan(
			&post.ID,
			&post.Title,
			&post.Content,
			&post.ImagePath,
			&categories,
			&post.Username,
			&post.CreatedAt,
			&post.LikeCount,
			&post.DislikeCount,
			&userLiked,
			&userDisliked,
		)
		if err != nil {
			SendError(w, "Error scanning posts", http.StatusInternalServerError)
			return
		}

		if categories.Valid {
			post.Categories = categories.String
		}
		if userLiked.Valid {
			post.UserLiked = userLiked.Bool
		}
		if userDisliked.Valid {
			post.UserDisliked = userDisliked.Bool
		}

		// Fetch comments for this post
		comments, err := GetCommentsForPost(post.ID, userID)
		if err != nil {
			SendError(w, "Error fetching comments", http.StatusInternalServerError)
			return
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"posts":      posts,
		"isLoggedIn": userID != "",
	})
}

// SendError sends a JSON error response
func SendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

package handlers

import (
	"encoding/json"
	"net/http"
)

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIdFromSession(w, r)
	if userID == "" {
		RenderError(w, r, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user info
	var user User
	err := db.QueryRow(
		"SELECT id, email, nickname FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Email, &user.Nickname)
	if err != nil {
		HandleDatabaseError(w, r, err)
		return
	}

	// Get user's created posts
	createdPosts, err := getCreatedPosts(userID)
	if err != nil {
		HandleDatabaseError(w, r, err)
		return
	}

	// Get posts liked by user
	likedPosts, err := getLikedPosts(userID)
	if err != nil {
		HandleDatabaseError(w, r, err)
		return
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"Nickname":     user.Nickname,
		"Email":        user.Email,
		"CreatedPosts": createdPosts,
		"LikedPosts":   likedPosts,
	})
}

func getCreatedPosts(userID string) ([]Post, error) {
	rows, err := db.Query(`
        SELECT 
            p.id, p.title, p.content, p.image_path, 
            GROUP_CONCAT(pc.category) as categories,
            p.created_at,
            COUNT(DISTINCT CASE WHEN l.is_like = 1 THEN l.user_id END) as like_count,
            COUNT(DISTINCT CASE WHEN l.is_like = 0 THEN l.user_id END) as dislike_count
        FROM posts p
        LEFT JOIN post_categories pc ON p.id = pc.post_id
        LEFT JOIN likes l ON p.id = l.post_id
        WHERE p.user_id = ?
        GROUP BY p.id
        ORDER BY p.created_at DESC
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		var categories string
		err := rows.Scan(
			&post.ID,
			&post.Title,
			&post.Content,
			&post.ImagePath,
			&categories,
			&post.CreatedAt,
			&post.LikeCount,
			&post.DislikeCount,
		)
		if err != nil {
			return nil, err
		}
		post.Categories = categories
		posts = append(posts, post)
	}
	return posts, nil
}

func getLikedPosts(userID string) ([]Post, error) {
	rows, err := db.Query(`
        SELECT 
            p.id, p.title, p.content, p.image_path,
            GROUP_CONCAT(pc.category) as categories,
            u.nickname,
            p.created_at,
            COUNT(DISTINCT CASE WHEN l2.is_like = 1 THEN l2.user_id END) as like_count,
            COUNT(DISTINCT CASE WHEN l2.is_like = 0 THEN l2.user_id END) as dislike_count
        FROM posts p
        JOIN likes l ON p.id = l.post_id AND l.user_id = ? AND l.is_like = 1
        LEFT JOIN post_categories pc ON p.id = pc.post_id
        LEFT JOIN likes l2 ON p.id = l2.post_id
        JOIN users u ON p.user_id = u.id
        GROUP BY p.id
        ORDER BY p.created_at DESC
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		var categories string
		err := rows.Scan(
			&post.ID,
			&post.Title,
			&post.Content,
			&post.ImagePath,
			&categories,
			&post.Nickname,
			&post.CreatedAt,
			&post.LikeCount,
			&post.DislikeCount,
		)
		if err != nil {
			return nil, err
		}
		post.Categories = categories
		posts = append(posts, post)
	}
	return posts, nil
}

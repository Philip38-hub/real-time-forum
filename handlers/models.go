package handlers

// User represents a user in the system
type User struct {
	ID       string
	Email    string
	Nickname string
	Password string
}

// Post represents a post in the forum
type Post struct {
	ID           int
	UserID       string
	Title        string
	Content      string
	ImagePath    string // Path to uploaded image
	Categories   string // Comma-separated list of categories
	Nickname     string // Author's nickname
	CreatedAt    string
	LikeCount    int       // Total number of likes
	DislikeCount int       // Total number of dislikes
	UserLiked    bool      // Whether the current user liked this post
	UserDisliked bool      // Whether the current user disliked this post
	Comments     []Comment // List of comments for this post
}

// Like represents a like/dislike on a post or comment
type Like struct {
	ID        int
	UserID    string // User who liked/disliked
	PostID    *int   // Post that was liked/disliked (null for comment likes)
	CommentID *int   // Comment that was liked/disliked (null for post likes)
	IsLike    bool   // true for like, false for dislike
}

// Comment represents a comment on a post
type Comment struct {
	ID           int
	PostID       int
	UserID       string // Changed from int to string to match User.ID
	Content      string
	CreatedAt    string
	Nickname     string
	ParentID     *int      // Parent comment ID, null for top-level comments
	Replies      []Comment // List of reply comments
	ReplyCount   int       // Number of replies
	LikeCount    int       // Number of likes
	DislikeCount int       // Number of dislikes
	UserLiked    bool      // Whether the current user liked this comment
	UserDisliked bool      // Whether the current user disliked this comment
}

// Session represents a user session
type Session struct {
	SessionID string
	UserID    string
}

// APIResponse represents the standard API response format
type APIResponse struct {
	Success    bool        `json:"success"`
	Error      string      `json:"error,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	IsLoggedIn bool        `json:"isLoggedIn"`
}

// API communication object
const api = {
    /**
     * General purpose fetch API wrapper with error handling
     */
    async fetch(url, options = {}) {
        try {
            const response = await fetch(url, options);

            // Check for authentication errors
            if (response.status === 401) {
                window.location.href = '/login';
                throw new Error('Authentication required');
            }

            // Check for successful response
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || `HTTP Error ${response.status}`);
            }

            // Parse JSON response
            return await response.json();
        } catch (error) {
            logger.error('API Error:', error);
            throw error;
        }
    },

    /**
     * Create a new post
     */
    async createPost(formData) {
        return await this.fetch('/post', {
            method: 'POST',
            body: formData
        });
    },

    /**
     * Add a comment to a post
     */
    async addComment(formData) {
        return await this.fetch('/comment', {
            method: 'POST',
            body: formData
        });
    },

    /**
     * Toggle like/dislike on a post
     */
    async togglePostLike(postId, isLike) {
        const formData = new URLSearchParams();
        formData.append('post_id', postId);
        formData.append('is_like', isLike);

        try {
            const data = await this.fetch('/like', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData
            });

            // Assuming data.reactions contains the updated reaction data
            if (data.success) {
                // Return the reactions data to update the UI
                return data.reactions;
            } else {
                throw new Error('Failed to toggle like on the post');
            }
        } catch (error) {
            console.error('Failed to toggle like on post:', error);
            throw error;
        }
    },

    /**
     * Toggle like/dislike on a comment
     */
    async toggleCommentLike(commentId, isLike) {
        const formData = new URLSearchParams();
        formData.append('comment_id', commentId);
        formData.append('is_like', isLike);

        try {
            const data = await this.fetch('/comment/like', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData
            });

            // Assuming data.reactions contains the updated reaction data
            if (data.success) {
                // Return the reactions data to update the UI
                return data.reactions;
            } else {
                throw new Error('Failed to toggle like on the post');
            }
        } catch (error) {
            console.error('Failed to toggle like on post:', error);
            throw error;
        }
    },
    
    /*       Fetch all users     */
    async fetchUsers() {
        return await this.fetch('/api/messages/users');
    },

    /*       Fetch messages with a specific user     */
    async fetchMessages(userId, page = 1, limit = 10) {
        return await this.fetch(`/api/messages/${userId}?page=${page}&limit=${limit}`);
    },

    /*     Send a message to a user      */
    async sendMessage(userId, content) {
        return await this.fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                receiverId: userId,
                content: content
            })
        });
    },

    /*     Register a new user      */
    async register(userData) {
        return await this.fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });
    },

    /*      Login user      */
    async login(credentials) {
        return await this.fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentials)
        });
    },

    /*     Logout user     */
    async logout() {
        return await this.fetch('/logout', {
            method: 'POST'
        });
    }
};
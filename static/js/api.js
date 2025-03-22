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

        return await this.fetch('/like', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData
        });
    },

    /**
     * Toggle like/dislike on a comment
     */
    async toggleCommentLike(commentId, isLike) {
        const formData = new URLSearchParams();
        formData.append('comment_id', commentId);
        formData.append('is_like', isLike);

        return await this.fetch('/comment/like', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData
        });
    }
};
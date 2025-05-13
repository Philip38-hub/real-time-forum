class Api {
    constructor() {
        this.baseUrl = ''; // Same origin for API calls
    }

    async request(endpoint, options = {}) {
        const config = {
            ...options,
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                ...options.headers
            },
            credentials: 'include'
        };

        // Add Content-Type only if not FormData or URLSearchParams
        if (options.body && !(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) {
            config.headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, config);

            // Handle unauthorized without redirect
            if (response.status === 401) {
                store.setUser(null);
                throw new Error('Unauthorized');
            }

            // For error responses
            if (!response.ok) {
                // Try to get error message from response
                try {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        throw new Error(errorData.error);
                    }
                } catch (parseError) {
                    // If can't parse JSON, use status text
                    throw new Error(`Request failed: ${response.statusText || response.status}`);
                }
            }

            // Always try to parse JSON for our API endpoints
            try {
                const data = await response.json();
                return data;
            } catch (parseError) {
                console.error('Failed to parse JSON response:', parseError);
                throw new Error('Invalid JSON response');
            }
        } catch (error) {
            console.error('API Error:', error);
            // Set the error in the store
            store.setError(error.message || 'An error occurred');
            throw error;
        }
    }

    // Authentication endpoints
    async login(identifier, password) {
        const response = await this.request('/login', {
            method: 'POST',
            body: JSON.stringify({ identifier, password }),
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.success) {
            await store.setUser(response.user);
        }
        return response;
    }

    async register(registrationData) {
        const response = await this.request('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(registrationData)
        });
        return response;
    }

    async logout() {
        try {
            // Close WebSocket connection before logging out
            if (window.webSocketManager && window.webSocketManager.socket) {
                window.webSocketManager.socket.close(1000, "User logged out");
            }

            // The server is returning a redirect, not JSON
            const response = await fetch('/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin'
            });

            // Don't try to parse JSON, just check if response was successful
            if (response.ok) {
                store.setUser(null);
                return true;
            } else {
                throw new Error(`Logout failed with status: ${response.status}`);
            }
        } catch (error) {
            console.error('Logout error:', error);
            throw error;
        }
    }
    // Post endpoints
    async getPosts() {
        try {
            const response = await this.request('/api/posts');
            if (response && response.success && Array.isArray(response.posts)) {
                return response.posts;
            } else {
                console.error('Invalid posts response format:', response);
                return [];
            }
        } catch (error) {
            console.error('Failed to fetch posts:', error);
            return [];
        }
    }

    async getPostsByCategory(category) {
        try {
            // Use fetch directly with proper headers
            const response = await fetch(`/filter?category=${encodeURIComponent(category)}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (data && data.success && Array.isArray(data.posts)) {
                // Remove any duplicates by ID
                const uniquePosts = Array.from(
                    new Map(data.posts.map(post => [post.ID, post])).values()
                );
                return uniquePosts;
            }

            console.error('Invalid filtered posts response format:', data);
            return [];
        } catch (error) {
            console.error('Failed to fetch filtered posts:', error);
            return [];
        }
    }

    async createPost(formData) {
        const response = await this.request('/post', {
            method: 'POST',
            headers: {}, // Let browser set correct content-type for FormData
            body: formData
        });
        return response;
    }

    // Like/Dislike endpoints
    async togglePostLike(postId, isLike) {
        const body = new URLSearchParams({
            post_id: postId,
            is_like: String(isLike)
        });
        const response = await this.request('/like', {
            method: 'POST',
            headers: {}, // Let fetch set Content-Type
            body
        });
        return response;
    }

    async toggleCommentLike(commentId, isLike) {
        const body = new URLSearchParams({
            comment_id: commentId,
            is_like: String(isLike)
        });
        const response = await this.request('/comment/like', {
            method: 'POST',
            headers: {}, // Let fetch set Content-Type
            body
        });
        return response;
    }

    // Comment endpoints
    async createComment(postId, content, parentId = null) {
        const params = { post_id: postId, content };
        if (parentId) params.parent_id = parentId;
        const body = new URLSearchParams(params);
        const response = await this.request('/comment', {
            method: 'POST',
            headers: {}, // Let fetch set Content-Type
            body
        });
        return response;
    }

    // Profile endpoints
    async getProfile() {
        const response = await this.request('/api/profile');
        return response;
    }

    // Session check
    async checkSession() {
        store.setUser(null);
        return new Promise(resolve => {
            // Do a minimal check of session state
            fetch('/api/posts', {
                method: 'HEAD',
                credentials: 'include'
            })
                .then(response => {
                    // If we get any response, consider it a success
                    // The actual auth state will be handled by individual routes
                    resolve(true);
                })
                .catch(() => {
                    resolve(false);
                });
        });
    }

    // OAuth endpoints
    async githubLogin() {
        window.location.href = '/auth/github';
    }

    async googleLogin() {
        window.location.href = '/auth/google';
    }
}

// Create and export a single API instance
const api = new Api();

const apiRequests = {
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
};

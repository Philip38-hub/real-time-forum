class Store {
    constructor() {
        this.state = {
            user: null,
            posts: [],
            categories: [
                'technology', 'general', 'lifestyle', 'entertainment',
                'gaming', 'food', 'business', 'religion', 'health',
                'music', 'sports', 'beauty', 'jobs'
            ],
            currentPost: null,
            isLoading: false,
            error: null
        };
        this.subscribers = [];
        this.loadUser();
    }

    subscribe(callback) {
        this.subscribers.push(callback);
        // Return unsubscribe function
        return () => {
            this.subscribers = this.subscribers.filter(sub => sub !== callback);
        };
    }

    notify() {
        return new Promise(resolve => {
            // Execute callbacks in next tick to ensure state is updated
            setTimeout(() => {
                this.subscribers.forEach(callback => callback(this.state));
                resolve();
            }, 0);
        });
    }

    async setState(newState) {
        this.state = { ...this.state, ...newState };
        await this.notify();
    }

    // User actions
    async setUser(user) {
        await this.setState({ user });
        if (user) {
            localStorage.setItem('user', JSON.stringify(user));
        } else {
            localStorage.removeItem('user');
        }
    }

    // Load user from localStorage
    loadUser() {
        const userData = localStorage.getItem('user');
        if (userData) {
            this.state.user = JSON.parse(userData);
        }
    }

    // Posts actions
    async setPosts(posts) {
        await this.setState({ posts: Array.isArray(posts) ? posts : [] });
    }

    addPost(post) {
        this.setState({ posts: [post, ...this.state.posts] });
    }

    updatePost(updatedPost) {
        const updatedPosts = this.state.posts.map(post => 
            post.ID === updatedPost.ID ? updatedPost : post
        );
        this.setState({ posts: updatedPosts });
    }

    setCurrentPost(post) {
        this.setState({ currentPost: post });
    }

    // Loading and error states
    setLoading(isLoading) {
        this.setState({ isLoading });
    }

    setError(error) {
        this.setState({ error });
    }

    // Like/Dislike actions
    updatePostLikes(postId, likeCount, dislikeCount) {
        const updatedPosts = this.state.posts.map(post => {
            if (post.ID === postId) {
                return { ...post, LikeCount: likeCount, DislikeCount: dislikeCount };
            }
            return post;
        });
        this.setState({ posts: updatedPosts });
    }

    updateCommentLikes(postId, commentId, likeCount, dislikeCount) {
        const updatedPosts = this.state.posts.map(post => {
            if (post.ID === postId) {
                const updatedComments = post.Comments.map(comment => {
                    if (comment.ID === commentId) {
                        return { ...comment, LikeCount: likeCount, DislikeCount: dislikeCount };
                    }
                    return comment;
                });
                return { ...post, Comments: updatedComments };
            }
            return post;
        });
        this.setState({ posts: updatedPosts });
    }

    // Comment actions
    addComment(postId, comment) {
        const updatedPosts = this.state.posts.map(post => {
            if (post.ID === postId) {
                return {
                    ...post,
                    Comments: [comment, ...(post.Comments || [])]
                };
            }
            return post;
        });
        this.setState({ posts: updatedPosts });
    }

    addReply(postId, parentCommentId, reply) {
        const updatedPosts = this.state.posts.map(post => {
            if (post.ID === postId) {
                const updatedComments = post.Comments.map(comment => {
                    if (comment.ID === parentCommentId) {
                        return {
                            ...comment,
                            Replies: [reply, ...(comment.Replies || [])]
                        };
                    }
                    return comment;
                });
                return { ...post, Comments: updatedComments };
            }
            return post;
        });
        this.setState({ posts: updatedPosts });
    }
}

// Create and export a single store instance
const store = new Store();
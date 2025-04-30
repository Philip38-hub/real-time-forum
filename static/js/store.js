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
            currentCategory: null,
            filteredPosts: new Map(), // Cache for filtered posts by category
            isLoading: false,
            error: null
        };
        this.subscribers = [];
        this.loadUser();
        this.loadFilteredPosts(); // Load filtered posts from localStorage
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

    // Load filtered posts from localStorage
    loadFilteredPosts() {
        const savedData = localStorage.getItem('filteredPosts');
        if (savedData) {
            try {
                const { posts, category } = JSON.parse(savedData);
                if (Array.isArray(posts) && category) {
                    const filteredPosts = new Map();
                    filteredPosts.set(category, posts);
                    this.state.filteredPosts = filteredPosts;
                    this.state.currentCategory = category;
                    this.state.posts = posts;
                }
            } catch (error) {
                console.error('Error loading filtered posts:', error);
            }
        }
    }

    // Posts actions
    async setPosts(posts, category = null) {
        const postsArray = Array.isArray(posts) ? posts : [];
        if (category) {
            // Keep existing filtered posts and update/add the current category
            const filteredPosts = new Map(this.state.filteredPosts);
            if (postsArray.length > 0) {
                // Only update cache if we have posts
                filteredPosts.set(category, postsArray);
                // Save to localStorage for persistence
                localStorage.setItem('filteredPosts', JSON.stringify({
                    posts: postsArray,
                    category
                }));
            } else if (filteredPosts.has(category)) {
                // If no posts but category exists in cache, use cached posts
                const cachedPosts = filteredPosts.get(category);
                if (cachedPosts && cachedPosts.length > 0) {
                    return await this.setState({
                        posts: cachedPosts,
                        currentCategory: category,
                        filteredPosts
                    });
                }
            }

            await this.setState({
                posts: postsArray,
                currentCategory: category,
                filteredPosts
            });
        } else {
            localStorage.removeItem('filteredPosts'); // Clear saved filtered posts
            await this.setState({
                posts: postsArray,
                currentCategory: null
            });
        }
    }

    // Get cached posts for a category
    getCachedPosts(category) {
        return this.state.filteredPosts.get(category);
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
            if (String(post.ID) === String(postId)) {
                return { ...post, LikeCount: likeCount, DislikeCount: dislikeCount };
            }
            return post;
        });
        this.setState({ posts: updatedPosts });
    }

    updateCommentLikes(postId, commentId, likeCount, dislikeCount, isLike = null) {
        const targetCommentId = String(commentId);
        const updatedPosts = this.state.posts.map(post => {
            if (String(post.ID) === String(postId)) {
                const updatedComments = post.Comments.map(comment => {
                    // Check if this is the target comment
                    if (String(comment.ID) === targetCommentId) {
                        const wasLiked = comment.UserLiked;
                        const wasDisliked = comment.UserDisliked;
                        let newUserLiked = wasLiked;
                        let newUserDisliked = wasDisliked;

                        if (isLike === true) {
                            newUserLiked = !wasLiked;
                            newUserDisliked = false;
                        } else if (isLike === false) {
                            newUserDisliked = !wasDisliked;
                            newUserLiked = false;
                        }

                        return {
                            ...comment,
                            LikeCount: likeCount,
                            DislikeCount: dislikeCount,
                            UserLiked: newUserLiked,
                            UserDisliked: newUserDisliked
                        };
                    }
                    // Check in replies if this comment has any
                    if (comment.Replies && Array.isArray(comment.Replies)) {
                        const updatedReplies = comment.Replies.map(reply => {
                            if (String(reply.ID) === targetCommentId) {
                                const wasLiked = reply.UserLiked;
                                const wasDisliked = reply.UserDisliked;
                                let newUserLiked = wasLiked;
                                let newUserDisliked = wasDisliked;

                                if (isLike === true) {
                                    newUserLiked = !wasLiked;
                                    newUserDisliked = false;
                                } else if (isLike === false) {
                                    newUserDisliked = !wasDisliked;
                                    newUserLiked = false;
                                }

                                return {
                                    ...reply,
                                    LikeCount: likeCount,
                                    DislikeCount: dislikeCount,
                                    UserLiked: newUserLiked,
                                    UserDisliked: newUserDisliked
                                };
                            }
                            return reply;
                        });
                        return { ...comment, Replies: updatedReplies };
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
            if (String(post.ID) === String(postId)) {
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
// App state management and main application entry point
const app = {
    isProcessing: false,

    // Initialize the application
    init() {
        this.attachEventListeners();
        webSocketManager.init();
        logger.info('Forum application initialized');
    },

    // Attach event listeners using event delegation
    attachEventListeners() {
        // Menu toggle
        const menuToggle = document.getElementById('menu-toggle');
        if (menuToggle) {
            menuToggle.addEventListener('click', () => UI.toggleSidebar());
        }

        // Create post button
        const createPostBtn = document.getElementById('create-post-btn');
        if (createPostBtn) {
            createPostBtn.addEventListener('click', (e) => {
                e.preventDefault();
                UI.toggleCreatePostForm();
            });
        }

        // Cancel post button
        const cancelPostBtn = document.getElementById('cancel-post-btn');
        if (cancelPostBtn) {
            cancelPostBtn.addEventListener('click', () => {
                UI.toggleCreatePostForm();
            });
        }

        // Create post form submission
        const createPostForm = document.getElementById('create-post-form');
        if (createPostForm) {
            createPostForm.addEventListener('submit', this.handleCreatePostSubmit.bind(this));
        }

        // Post actions: Event delegation for comments, likes, dislikes
        document.addEventListener('click', this.handlePostActions.bind(this));

        // Comment form submissions: Event delegation for all comment forms
        document.addEventListener('submit', this.handleFormSubmissions.bind(this));
    },

    // Handle post creation form submission
    async handleCreatePostSubmit(event) {
        event.preventDefault();

        if (this.isProcessing) return;

        // Form validation
        if (!validateFormContent(event.target) || !validateCategories()) {
            return;
        }

        try {
            this.isProcessing = true;
            const formData = new FormData(event.target);

            // Submit form via API
            const response = await api.createPost(formData);

            if (response && response.success) {
                // Clear form and hide it
                event.target.reset();
                UI.toggleCreatePostForm();

                // Display success message
                // alert('Post created successfully!');

                // If WebSocket isn't working, manually add the post to UI
                if (!webSocketManager.isConnected()) {
                    UI.addNewPost(response.post);
                }
            } else {
                throw new Error(response.message || 'Failed to create post');
            }
        } catch (error) {
            logger.error('Error creating post:', error);
            alert(`Error creating post: ${error.message || 'Unknown error'}`);
        } finally {
            this.isProcessing = false;
        }
    },

    // Handle post actions (comments, likes, dislikes) with event delegation
    handlePostActions(event) {
        // Handle comment section toggle
        if (event.target.closest('.comment-button')) {
            const button = event.target.closest('.comment-button');
            const postId = getIdFromElement(button, 'data-post-id');
            if (postId) {
                UI.toggleCommentSection(postId);
            }
            return;
        }

        // Handle reply toggle
        if (event.target.closest('.reply-button')) {
            const button = event.target.closest('.reply-button');
            const commentId = getIdFromElement(button, 'data-comment-id');
            if (commentId) {
                UI.toggleReplyForm(commentId);
            }
            return;
        }

        // Handle likes and dislikes for posts and comments
        if (event.target.closest('.like-button, .dislike-button')) {
            this.handleLikeAction(event);
            return;
        }
    },

    // Handle like/dislike button clicks for posts and comments
    async handleLikeAction(event) {
        const button = event.target.closest('.like-button, .dislike-button');
        if (!button || this.isProcessing) return;

        try {
            this.isProcessing = true;

            // Determine if like or dislike
            const isLike = button.classList.contains('like-button');

            // Determine if post or comment
            const postId = getIdFromElement(button, 'data-post-id');
            const commentId = getIdFromElement(button, 'data-comment-id');

            let response;

            // Handle post like/dislike
            if (postId) {
                response = await api.togglePostLike(postId, isLike);
                if (response && response.success) {
                    UI.updateLikeUI(button, response.data);
                }
            }
            // Handle comment like/dislike
            else if (commentId) {
                response = await api.toggleCommentLike(commentId, isLike);
                if (response && response.success) {
                    UI.updateLikeUI(button, response.data);
                }
            }

        } catch (error) {
            logger.error('Error handling like/dislike:', error);
            alert('Failed to update like status');
        } finally {
            this.isProcessing = false;
        }
    },

    // Handle form submissions for comments and replies with event delegation
    async handleFormSubmissions(event) {
        const form = event.target;

        // Comment form submission
        if (form.classList.contains('comment-form-element')) {
            event.preventDefault();
            await this.handleCommentSubmit(form, false);
            return;
        }

        // Reply form submission
        if (form.classList.contains('reply-form-element')) {
            event.preventDefault();
            await this.handleCommentSubmit(form, true);
            return;
        }
    },

    // Handle comment and reply submissions
    async handleCommentSubmit(form, isReply) {
        if (this.isProcessing) return;

        // Validate form content
        if (!validateFormContent(form)) {
            return;
        }

        try {
            this.isProcessing = true;
            const formData = new FormData(form);

            // Submit via API
            const response = await api.addComment(formData);

            if (response && response.success) {
                // Clear the form
                UI.clearForm(form);

                // Close reply form if it's a reply
                if (isReply) {
                    const commentId = getIdFromElement(form, 'data-comment-id');
                    if (commentId) {
                        UI.toggleReplyForm(commentId);
                    }
                }

                // If WebSocket isn't working, manually add to UI
                if (!webSocketManager.isConnected()) {
                    UI.addNewComment(response.comment, isReply);
                }
            } else {
                throw new Error(response.message || 'Failed to post comment');
            }
        } catch (error) {
            logger.error('Error posting comment:', error);
            alert(`Error posting comment: ${error.message || 'Unknown error'}`);
        } finally {
            this.isProcessing = false;
        }
    }
};

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
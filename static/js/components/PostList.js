class PostList {
    constructor() {
        this.container = document.getElementById('main-container');
        
        // Subscribe to posts changes
        store.subscribe((state) => {
            if (this.lastPosts !== state.posts) {
                this.lastPosts = state.posts;
                this.render();
            }
        });
    }

    getCategoryTitle() {
        const params = new URLSearchParams(window.location.search);
        const category = params.get('category');
        return category ? category.charAt(0).toUpperCase() + category.slice(1) : 'All Posts';
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }

    render() {
        const user = store.state.user;
        const posts = store.state.posts;
        const categoryTitle = this.getCategoryTitle();
        
        try {
            this.container.innerHTML = `
                <h1 id="postsHeading">${categoryTitle}</h1>
                <div id="posts">
                    ${Array.isArray(posts) && posts.length > 0
                        ? posts.map(post => this.renderPost(post, user)).join('')
                        : '<p>No posts available.</p>'}
                </div>
            `;

            // Add event listeners after rendering
            this.addEventListeners();
        } catch (error) {
            console.error('Error rendering posts:', error);
            this.container.innerHTML = '<p>Error rendering posts. Please try again.</p>';
        }
    }

    renderPost(post, user) {
        return `
            <div class="post" data-post-id="${post.ID}" data-category="${post.Categories}">
                <p class="posted-on">Posted on: ${this.formatDate(post.CreatedAt)}</p>
                <strong>
                    <p>${post.Username}</p>
                </strong>
                <h3>${post.Title}</h3>
                <p>${post.Content}</p>
                ${post.ImagePath ? `
                    <img src="${post.ImagePath}" alt="Post Image" class="post-image">
                ` : ''}
                <p class="categories">Categories: <span>${post.Categories}</span></p>
                
                <div class="post-actions">
                    <button class="like-button ${post.UserLiked ? 'active' : ''}">
                        <i class="fas fa-thumbs-up"></i> 
                        <span class="like-count">${post.LikeCount}</span>
                    </button>
                    <button class="dislike-button ${post.UserDisliked ? 'active' : ''}">
                        <i class="fas fa-thumbs-down"></i> 
                        <span class="dislike-count">${post.DislikeCount}</span>
                    </button>
                    <button class="comment-button">
                        <i class="fas fa-comment"></i> Comments
                    </button>
                </div>

                <!-- Comments Section -->
                <div class="comments-section" id="comments-${post.ID}" style="display: none;">
                    ${comments.renderCommentSection(post.ID, Array.isArray(post.Comments) ? post.Comments : [])}
                </div>
            </div>
        `;
    }

    addEventListeners() {
        this.container.querySelectorAll('.like-button').forEach(button => {
            const postId = button.closest('.post').dataset.postId;
            button.addEventListener('click', () => this.handleLike(postId, true));
        });

        this.container.querySelectorAll('.dislike-button').forEach(button => {
            const postId = button.closest('.post').dataset.postId;
            button.addEventListener('click', () => this.handleLike(postId, false));
        });
        this.container.querySelectorAll('.comment-button').forEach(button => {
            const postId = button.closest('.post').dataset.postId;
            button.addEventListener('click', () => this.toggleComments(postId));
        });
    }

    async handleLike(postId, isLike) {
        if (!store.state.user) {
            router.navigate('/login');
            return;
        }

        try {
            const response = await api.togglePostLike(postId, isLike);
            store.updatePostLikes(postId, response.like_count, response.dislike_count);
        } catch (error) {
            store.setError('Failed to update like status');
        }
    }

    toggleComments(postId) {
        const commentsSection = document.getElementById(`comments-${postId}`);
        commentsSection.style.display = commentsSection.style.display === 'none' ? 'block' : 'none';
    }
}

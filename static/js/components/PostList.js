const openCommentsSections = new Set();

class PostList {
    constructor() {
        this.container = document.getElementById('main-container');
        
        store.subscribe((state) => {
            this.lastPosts = state.posts;
            this.render();
        });
        this.handleDelegatedClick = this.handleDelegatedClick.bind(this);
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
        const posts = store.state.posts || [];
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
            // Add event delegation listener after rendering
            this.container.removeEventListener('click', this.handleDelegatedClick); // Prevent duplicate listeners
            this.container.addEventListener('click', this.handleDelegatedClick);
            // Restore open comment sections after rendering
            this.restoreOpenCommentsSections();
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
                    <p>${post.Nickname}</p>
                </strong>
                <h3>${post.Title}</h3>
                <p>${post.Content}</p>
                ${post.ImagePath ? `
                    <img src="${post.ImagePath}" alt="Post Image" class="post-image">
                ` : ''}
                <p class="categories">Categories: <span>${post.Categories}</span></p>
                
                <div class="post-actions">
                    <button class="post-like-button ${post.UserLiked ? 'active' : ''}">
                        <i class="fas fa-thumbs-up"></i>
                        <span class="post-like-count">${post.LikeCount}</span>
                    </button>
                    <button class="post-dislike-button ${post.UserDisliked ? 'active' : ''}">
                        <i class="fas fa-thumbs-down"></i>
                        <span class="post-dislike-count">${post.DislikeCount}</span>
                    </button>
                    <button class="post-comment-button">
                        <i class="fas fa-comment"></i> Comments
                    </button>
                </div>

                <!-- Comments Section -->
                <div class="comments-section" id="comments-${post.ID}" style="display: none;">
                    <button class="close-comments-btn" data-post-id="${post.ID}" title="Close Comments" style="float:right; margin:5px;">&times;</button>
                    ${comments.renderCommentSection(post.ID, Array.isArray(post.Comments) ? post.Comments : [])}
                </div>
            </div>
        `;
    }

    // Event delegation handler
    async handleDelegatedClick(event) {
        const likeBtn = event.target.closest('.post-like-button');
        const dislikeBtn = event.target.closest('.post-dislike-button');
        const commentBtn = event.target.closest('.post-comment-button');
        const closeCommentsBtn = event.target.closest('.close-comments-btn');
        const postDiv = event.target.closest('.post');
        if (!postDiv) return;
        const postId = postDiv.dataset.postId;
        if (likeBtn) {
            event.preventDefault();
            this.optimisticLike(postId, true, likeBtn);
            return;
        }
        if (dislikeBtn) {
            event.preventDefault();
            this.optimisticLike(postId, false, dislikeBtn);
            return;
        }
        if (commentBtn) {
            event.preventDefault();
            this.toggleComments(postId);
            return;
        }
        if (closeCommentsBtn) {
            event.preventDefault();
            this.closeCommentsSection(postId);
            return;
        }
    }

    // Optimistic like/dislike
    async optimisticLike(postId, isLike, btnElem) {
        if (!store.state.user) {
            router.navigate('/login');
            return;
        }
        // Optimistically update UI
        const posts = store.state.posts;
        const postIdx = posts.findIndex(p => String(p.ID) === String(postId));
        if (postIdx === -1) return;
        const post = posts[postIdx];
        // Toggle logic: if already liked/disliked, undo; else, do
        let newLikeCount = post.LikeCount;
        let newDislikeCount = post.DislikeCount;
        let newUserLiked = post.UserLiked;
        let newUserDisliked = post.UserDisliked;
        if (isLike) {
            if (post.UserLiked) {
                newLikeCount -= 1;
                newUserLiked = false;
            } else {
                newLikeCount += 1;
                newUserLiked = true;
                if (post.UserDisliked) {
                    newDislikeCount -= 1;
                    newUserDisliked = false;
                }
            }
        } else {
            if (post.UserDisliked) {
                newDislikeCount -= 1;
                newUserDisliked = false;
            } else {
                newDislikeCount += 1;
                newUserDisliked = true;
                if (post.UserLiked) {
                    newLikeCount -= 1;
                    newUserLiked = false;
                }
            }
        }
        const updatedPost = { ...post, LikeCount: newLikeCount, DislikeCount: newDislikeCount, UserLiked: newUserLiked, UserDisliked: newUserDisliked };
        store.updatePost(updatedPost);
        try {
            const response = await api.togglePostLike(postId, isLike);
            const serverLikeCount = response.like_count;
            const serverDislikeCount = response.dislike_count;
            if (response && (serverLikeCount !== newLikeCount || serverDislikeCount !== newDislikeCount)) {
                store.updatePostLikes(postId, serverLikeCount, serverDislikeCount);
            }
        } catch (error) {
            store.updatePost(post);
            store.setError('Failed to update like status');
        }
    }

    restoreOpenCommentsSections() {
        openCommentsSections.forEach(postId => {
            const section = document.getElementById(`comments-${postId}`);
            if (section) {
                section.style.display = 'block';
            }
        });
    }

    toggleComments(postId) {
        const commentsSection = document.getElementById(`comments-${postId}`);
        if (commentsSection) {
            if (commentsSection.style.display === 'none' || commentsSection.style.display === '') {
                const post = store.state.posts.find(p => String(p.ID) === String(postId));
                if (post) {
                    commentsSection.innerHTML = `
                        <button class="close-comments-btn" data-post-id="${postId}" title="Close Comments" style="float:right; margin:5px;">&times;</button>
                        ${comments.renderCommentSection(postId, Array.isArray(post.Comments) ? post.Comments : [])}
                    `;
                }
                commentsSection.style.display = 'block';
                openCommentsSections.add(postId);
            } else {
                commentsSection.style.display = 'none';
                openCommentsSections.delete(postId);
            }
        }
    }

    closeCommentsSection(postId) {
        const section = document.getElementById(`comments-${postId}`);
        if (section) {
            section.style.display = 'none';
        }
        openCommentsSections.delete(postId);
    }
}

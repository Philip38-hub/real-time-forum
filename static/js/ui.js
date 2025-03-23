// User interface management
const UI = {
    // Post creation UI
    toggleCreatePostForm() {
        const createPostForm = document.getElementById('createPostForm');
        const postsList = document.getElementById('posts');
        const postsHeading = document.getElementById('postsHeading');

        toggleElement(createPostForm);

        if (!createPostForm.classList.contains('hidden')) {
            hideElement(postsList);
            hideElement(postsHeading);
        } else {
            showElement(postsList);
            showElement(postsHeading);
        }
    },

    // Comment UI
    toggleCommentSection(postId) {
        const commentsSection = document.getElementById(`comments-${postId}`);
        const commentForm = document.getElementById(`comment-form-${postId}`);

        if (commentsSection) {
            toggleElement(commentsSection);

            if (!commentsSection.classList.contains('hidden')) {
                showElement(commentForm);
            } else {
                hideElement(commentForm);
            }
        }
    },

    // Reply UI
    toggleReplyForm(commentId) {
        const replyForm = document.getElementById(`reply-form-${commentId}`);
        if (replyForm) {
            toggleElement(replyForm);
        }
    },

    // Mobile menu
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        toggleElement(sidebar);
    },

    // Update UI after like/dislike
    updateLikeUI(element, data) {
        if (!element || !data) {
            console.error('Failed to update like status: Element or data is undefined.');
            return;
        }

        const isPost = element.hasAttribute('data-post-id');
        const container = isPost
            ? element.closest('.post')
            : element.closest('.comment');

        if (!container) {
            console.error('Failed to find container for the like button.');
            return;
        }

        const likeButton = container.querySelector('.like-button');
        const dislikeButton = container.querySelector('.dislike-button');

        if (!likeButton || !dislikeButton) {
            console.error('Like/Dislike buttons not found in the container.');
            return;
        }

        const likeCount = likeButton.querySelector('.like-count');
        const dislikeCount = dislikeButton.querySelector('.dislike-count');

        // Update the counts
        if (isPost) {
            if (likeCount) likeCount.textContent = data.like_count;
            if (dislikeCount) dislikeCount.textContent = data.dislike_count;
        } else {
            if (likeCount) likeCount.textContent = data.like_count;
            if (dislikeCount) dislikeCount.textContent = data.dislike_count;
        }

        // Update button styles
        if ((isPost && data.user_liked === true) || (!isPost && data.userLiked === true)) {
            likeButton.classList.add('active');
            dislikeButton.classList.remove('active');
        } else if ((isPost && data.user_liked === false) || (!isPost && data.userLiked === false)) {
            dislikeButton.classList.add('active');
            likeButton.classList.remove('active');
        } else {
            likeButton.classList.remove('active');
            dislikeButton.classList.remove('active');
        }
    },

    // Add a new post to the UI
    addNewPost(post) {
        const postContainer = document.getElementById('posts');
        if (!postContainer) return;

        const postHtml = `
            <div class="post" data-category="${post.Categories}" data-post-id="${post.ID}">
                <p class="posted-on">Posted on: ${post.CreatedAt}</p>
                <strong>
                    <p>${post.Username}</p>
                </strong>
                <h3>${post.Title}</h3>
                <p>${post.Content}</p>
                ${post.ImagePath ? `<img src="${post.ImagePath}" alt="Post Image" class="post-image">` : ""}
                <p class="categories">Categories: <span>${post.Categories}</span></p>
                <div class="post-actions">
                    <button class="like-button" data-post-id="${post.ID}" data-action="like">
                        <i class="fas fa-thumbs-up"></i> <span class="like-count">0</span>
                    </button>
                    <button class="dislike-button" data-post-id="${post.ID}" data-action="dislike">
                        <i class="fas fa-thumbs-down"></i> <span class="dislike-count">0</span>
                    </button>
                    <button class="comment-button" data-post-id="${post.ID}">
                        <i class="fas fa-comment"></i> Comments
                    </button>
                </div>
                <div class="comments-section hidden" id="comments-${post.ID}">
                    <div class="comment-form hidden" id="comment-form-${post.ID}">
                        <form class="comment-form-element" data-post-id="${post.ID}">
                            <input type="hidden" name="post_id" value="${post.ID}">
                            <textarea name="content" placeholder="Write your comment..." required></textarea>
                            <button type="submit">Comment</button>
                        </form>
                    </div>
                </div>
            </div>
        `;

        // Create element and add to top of posts
        const postElement = createElementFromHTML(postHtml);
        postContainer.prepend(postElement);
    },

    // Add a new comment to the UI
    addNewComment(comment, isReply = false) {
        if (isReply) {
            const parentComment = document.querySelector(`.comment[data-comment-id="${comment.ParentID}"]`);
            if (!parentComment) return;

            // Find or create replies container
            let repliesContainer = parentComment.querySelector('.replies');
            if (!repliesContainer) {
                repliesContainer = document.createElement('div');
                repliesContainer.className = 'replies';
                parentComment.appendChild(repliesContainer);
            }

            // Create the reply element
            const replyHtml = `
                <div class="comment reply" data-comment-id="${comment.ID}">
                    <div class="comment-content">${comment.Content}</div>
                    <div class="comment-meta">
                        <span class="comment-author">Posted by ${comment.Username}</span>
                        <span class="comment-date">${comment.CreatedAt}</span>
                    </div>
                    <div class="comment-actions">
                        <button class="like-button" data-comment-id="${comment.ID}" data-action="like">
                            <i class="fas fa-thumbs-up"></i> <span class="like-count">0</span>
                        </button>
                        <button class="dislike-button" data-comment-id="${comment.ID}" data-action="dislike">
                            <i class="fas fa-thumbs-down"></i> <span class="dislike-count">0</span>
                        </button>
                    </div>
                </div>
            `;

            const replyElement = createElementFromHTML(replyHtml);
            repliesContainer.appendChild(replyElement);

            // Update reply count display
            const replyButton = parentComment.querySelector('.reply-button');
            if (replyButton) {
                const currentCountMatch = replyButton.textContent.match(/\((\d+)\)/);
                const currentCount = currentCountMatch ? parseInt(currentCountMatch[1]) : 0;
                const newCount = currentCount + 1;
                replyButton.textContent = `Reply (${newCount})`;
            }
        } else {
            // Add top-level comment
            const commentsSection = document.getElementById(`comments-${comment.PostID}`);
            if (!commentsSection) return;

            const commentHtml = `
                <div class="comment" data-comment-id="${comment.ID}">
                    <div class="comment-content">${comment.Content}</div>
                    <div class="comment-meta">
                        <span class="comment-author">Posted by ${comment.Username}</span>
                        <span class="comment-date">${comment.CreatedAt}</span>
                    </div>
                    <div class="comment-actions">
                        <button class="like-button" data-comment-id="${comment.ID}" data-action="like">
                            <i class="fas fa-thumbs-up"></i> <span class="like-count">${comment.LikeCount || 0}</span>
                        </button>
                        <button class="dislike-button" data-comment-id="${comment.ID}" data-action="dislike">
                            <i class="fas fa-thumbs-down"></i> <span class="dislike-count">${comment.DislikeCount || 0}</span>
                        </button>
                        <button class="reply-button" data-comment-id="${comment.ID}">
                            Reply
                        </button>
                    </div>
                    <div class="reply-form hidden" id="reply-form-${comment.ID}">
                        <form class="reply-form-element" data-comment-id="${comment.ID}">
                            <input type="hidden" name="post_id" value="${comment.PostID}">
                            <input type="hidden" name="parent_id" value="${comment.ID}">
                            <textarea name="content" placeholder="Write your reply..." required></textarea>
                            <button type="submit">Reply</button>
                        </form>
                    </div>
                    <div class="replies" id="replies-${comment.ID}"></div>
                </div>
            `;

            const commentElement = createElementFromHTML(commentHtml);
            commentsSection.appendChild(commentElement);
        }
    },

    // Clear a form after submission
    clearForm(form) {
        if (form) {
            const textareas = form.querySelectorAll('textarea');
            textareas.forEach(textarea => {
                textarea.value = '';
            });
        }
    }
};
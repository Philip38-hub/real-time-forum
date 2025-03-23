class Comments {
    constructor() {
        this.user = store.state.user;
        
        // Subscribe to user state changes
        store.subscribe((state) => {
            if (this.user !== state.user) {
                this.user = state.user;
            }
        });
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }

    renderCommentSection(postId, comments = []) {
        return `
            <div class="comments-section" id="comments-${postId}">
                ${this.renderCommentForm(postId)}
                <div class="comments-list">
                    ${comments.map(comment => this.renderComment(comment)).join('')}
                </div>
            </div>
        `;
    }

    renderCommentForm(postId) {
        if (!this.user) {
            return '<p>Please <a href="/login">login</a> to comment.</p>';
        }

        return `
            <div class="comment-form" id="comment-form-${postId}">
                <form onsubmit="comments.handleSubmit(event, '${postId}')">
                    <textarea name="content" placeholder="Write your comment..." required></textarea>
                    <button type="submit">Comment</button>
                </form>
            </div>
        `;
    }

    renderComment(comment) {
        return `
            <div class="comment" data-comment-id="${comment.ID}">
                <div class="comment-content">${comment.Content}</div>
                <div class="comment-meta">
                    <span class="comment-author">Posted by ${comment.Username}</span>
                    <span class="comment-date">${this.formatDate(comment.CreatedAt)}</span>
                </div>
                ${this.user ? this.renderCommentActions(comment) : ''}
                ${this.renderReplyForm(comment)}
                ${comment.Replies && comment.Replies.length > 0 ? `
                    <div class="replies">
                        ${comment.Replies.map(reply => this.renderComment(reply)).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }

    renderCommentActions(comment) {
        return `
            <div class="comment-actions">
                <button class="like-button ${comment.UserLiked ? 'active' : ''}" 
                        onclick="comments.handleLike('${comment.ID}', true)">
                    <i class="fas fa-thumbs-up"></i> 
                    <span class="like-count">${comment.LikeCount}</span>
                </button>
                <button class="dislike-button ${comment.UserDisliked ? 'active' : ''}" 
                        onclick="comments.handleLike('${comment.ID}', false)">
                    <i class="fas fa-thumbs-down"></i> 
                    <span class="dislike-count">${comment.DislikeCount}</span>
                </button>
                <button class="reply-button" onclick="comments.toggleReplyForm('${comment.ID}')">
                    Reply${comment.ReplyCount > 0 ? ` (${comment.ReplyCount})` : ''}
                </button>
            </div>
        `;
    }

    renderReplyForm(comment) {
        if (!this.user) return '';

        return `
            <div class="reply-form" id="reply-form-${comment.ID}" style="display: none;">
                <form onsubmit="comments.handleReplySubmit(event, '${comment.PostID}', '${comment.ID}')">
                    <textarea name="content" placeholder="Write your reply..." required></textarea>
                    <button type="submit">Reply</button>
                </form>
            </div>
        `;
    }

    async handleSubmit(event, postId) {
        event.preventDefault();
        const form = event.target;
        const content = form.content.value.trim();

        if (!content) {
            store.setError('Comment cannot be empty');
            return;
        }

        try {
            store.setLoading(true);
            const response = await api.createComment(postId, content);
            store.addComment(postId, response.comment);
            form.reset();
        } catch (error) {
            store.setError('Failed to post comment');
        } finally {
            store.setLoading(false);
        }
    }

    async handleReplySubmit(event, postId, parentId) {
        event.preventDefault();
        const form = event.target;
        const content = form.content.value.trim();

        if (!content) {
            store.setError('Reply cannot be empty');
            return;
        }

        try {
            store.setLoading(true);
            const response = await api.createComment(postId, content, parentId);
            store.addReply(postId, parentId, response.comment);
            form.reset();
            this.toggleReplyForm(parentId);
        } catch (error) {
            store.setError('Failed to post reply');
        } finally {
            store.setLoading(false);
        }
    }

    async handleLike(commentId, isLike) {
        if (!this.user) {
            router.navigate('/login');
            return;
        }

        try {
            store.setLoading(true);
            const response = await api.toggleCommentLike(commentId, isLike);
            const comment = this.findComment(commentId);
            if (comment) {
                store.updateCommentLikes(comment.PostID, commentId, response.likeCount, response.dislikeCount);
            }
        } catch (error) {
            store.setError('Failed to update comment like status');
        } finally {
            store.setLoading(false);
        }
    }

    toggleReplyForm(commentId) {
        const replyForm = document.getElementById(`reply-form-${commentId}`);
        if (replyForm) {
            replyForm.style.display = replyForm.style.display === 'none' ? 'block' : 'none';
        }
    }

    findComment(commentId, posts = store.state.posts) {
        for (const post of posts) {
            if (!post.Comments) continue;
            
            for (const comment of post.Comments) {
                if (comment.ID === commentId) {
                    return comment;
                }
                if (comment.Replies) {
                    for (const reply of comment.Replies) {
                        if (reply.ID === commentId) {
                            return reply;
                        }
                    }
                }
            }
        }
        return null;
    }
}

// Create global reference for event handlers
const comments = new Comments();
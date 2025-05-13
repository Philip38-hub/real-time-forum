class Comments {
    constructor() {
        this.user = store.state.user;
        this.posts = store.state.posts;

        // Subscribe to state changes
        store.subscribe((state) => {
            if (this.user !== state.user) {
                this.user = state.user;
            }
            if (this.posts !== state.posts) {
                this.posts = state.posts;
                // Re-render all comments when posts update
                this.reRenderComments();
            }
        });
    }

    reRenderComments() {
        const commentSections = document.querySelectorAll('.comments-section[id^="comments-"]');
        commentSections.forEach(section => {
            const postId = section.id.replace('comments-', '');
            const post = this.posts.find(p => String(p.ID) === String(postId));
            if (post && post.Comments) {
                section.innerHTML = this.renderCommentSection(postId, post.Comments);
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
        if (!comment || !comment.ID) return '';

        return `
            <div class="comment" data-comment-id="${comment.ID}">
                <div class="comment-content">${comment.Content || ''}</div>
                <div class="comment-meta">
                    <span class="comment-author">Posted by ${comment.Nickname || 'Anonymous'}</span>
                    <span class="comment-date">${this.formatDate(comment.CreatedAt)}</span>
                </div>
                ${this.user ? this.renderCommentActions(comment) : ''}
                ${this.renderReplyForm(comment)}
                ${Array.isArray(comment.Replies) && comment.Replies.length > 0 ? `
                    <div class="replies">
                        ${comment.Replies.map(reply => this.renderComment(reply)).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }

    renderCommentActions(comment) {
        if (!comment || !comment.ID) return '';

        // Check if this comment is a reply (has a parent_id)
        const isReply = comment.ParentID !== null && comment.ParentID !== undefined;

        return `
            <div class="comment-actions">
                <button class="comment-like-button ${comment.UserLiked ? 'active' : ''}"
                        onclick="comments.handleLike('${comment.ID}', true)">
                    <i class="fas fa-thumbs-up"></i>
                    <span class="comment-like-count">${comment.LikeCount || 0}</span>
                </button>
                <button class="comment-dislike-button ${comment.UserDisliked ? 'active' : ''}"
                        onclick="comments.handleLike('${comment.ID}', false)">
                    <i class="fas fa-thumbs-down"></i>
                    <span class="comment-dislike-count">${comment.DislikeCount || 0}</span>
                </button>
                ${!isReply ? `
                <button class="reply-button" onclick="comments.toggleReplyForm('${comment.ID}')">
                    Reply${comment.ReplyCount && comment.ReplyCount > 0 ? ` (${comment.ReplyCount})` : ''}
                </button>
                ` : ''}
            </div>
        `;
    }

    renderReplyForm(comment) {
        // Don't render reply form for replies
        if (!this.user || (comment.ParentID !== null && comment.ParentID !== undefined)) return '';

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
            // --- Force full post list re-render after adding comment ---
            if (typeof postList !== 'undefined' && postList.render) {
                postList.render();
            }
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

            // Force re-render of the specific comment section
            const commentElement = document.querySelector(`[data-comment-id="${parentId}"]`);
            if (commentElement) {
                const post = store.state.posts.find(p => String(p.ID) === String(postId));
                if (post) {
                    const comment = post.Comments.find(c => String(c.ID) === String(parentId));
                    if (comment) {
                        // Update the replies section
                        const repliesSection = commentElement.querySelector('.replies');
                        if (repliesSection) {
                            repliesSection.innerHTML = comment.Replies.map(reply => this.renderComment(reply)).join('');
                        } else {
                            // Create replies section if it doesn't exist
                            const newRepliesSection = document.createElement('div');
                            newRepliesSection.className = 'replies';
                            newRepliesSection.innerHTML = comment.Replies.map(reply => this.renderComment(reply)).join('');
                            commentElement.appendChild(newRepliesSection);
                        }
                    }
                }
            }

            // Force full post list re-render as a fallback
            if (typeof postList !== 'undefined' && postList.render) {
                postList.render();
            }
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

        // Get comment and post before making the API call
        const result = this.findComment(commentId);
        if (!result) {
            store.setError('Comment not found');
            return;
        }

        try {
            // Make the API call immediately
            const response = await api.toggleCommentLike(commentId, isLike);

            // Update the state with the server response
            store.updateCommentLikes(
                result.post.ID,
                commentId,
                response.likeCount,
                response.dislikeCount,
                isLike
            );
        } catch (error) {
            store.setError('Failed to update comment like status');
        }
    }

    toggleReplyForm(commentId) {
        const replyForm = document.getElementById(`reply-form-${commentId}`);
        if (replyForm) {
            replyForm.style.display = replyForm.style.display === 'none' ? 'block' : 'none';
        }
    }

    findComment(commentId, posts = store.state.posts) {
        const targetId = String(commentId);

        for (const post of posts) {
            if (!post.Comments) continue;

            for (const comment of post.Comments) {
                if (String(comment.ID) === targetId) {
                    return { comment, post };
                }
                if (comment.Replies) {
                    for (const reply of comment.Replies) {
                        if (String(reply.ID) === targetId) {
                            return { comment: reply, post };
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
class Profile {
    constructor() {
        this.container = document.getElementById('main-container');
        this.render();
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }

    renderPost(post, showAuthor = false) {
        return `
            <article class="post">
                <h3>${post.Title}</h3>
                <p class="post-content">${post.Content}</p>
                ${post.ImagePath ? `
                    <img src="${post.ImagePath}" alt="Post Image" class="post-image">
                ` : ''}
                <div class="post-meta">
                    ${showAuthor ? `
                        <span class="author">
                            <i class="fas fa-user"></i> ${post.Nickname}
                        </span>
                    ` : ''}
                    ${post.Categories ? `
                        <span class="categories">
                            <i class="fas fa-tags"></i> ${post.Categories}
                        </span>
                    ` : ''}
                    <span class="likes">
                        <i class="fas fa-thumbs-up"></i> ${post.LikeCount}
                    </span>
                    <span class="dislikes">
                        <i class="fas fa-thumbs-down"></i> ${post.DislikeCount}
                    </span>
                    <span class="date">
                        <i class="far fa-clock"></i> ${this.formatDate(post.CreatedAt)}
                    </span>
                </div>
            </article>
        `;
    }

    async render() {
        if (!store.state.user) {
            router.navigate('/login', true);
            return;
        }

        try {
            store.setLoading(true);
            const profileData = await api.getProfile();
            // Only render the profile content, not the header
            this.container.innerHTML = `
                <div class="profile-container">
                    <div class="profile-header">
                        <h1>
                            <i class="fas fa-user-circle"></i> ${profileData.Nickname}'s Profile
                        </h1>
                        <p>
                            <i class="fas fa-envelope"></i> ${profileData.Email}
                        </p>
                        <p>
                            <i class="fas fa-calendar-alt"></i> Joined: ${profileData.CreatedAt ? new Date(profileData.CreatedAt).toLocaleDateString() : 'N/A'}
                        </p>
                        <p>
                            <i class="fas fa-id-badge"></i> User ID: ${profileData.ID || 'N/A'}
                        </p>
                    </div>
                    <div class="profile-sections">
                        <section class="profile-section">
                            <h2><i class="fas fa-pencil-alt"></i> Your Posts</h2>
                            ${profileData.CreatedPosts && profileData.CreatedPosts.length ? 
                                profileData.CreatedPosts.map(post => this.renderPost(post)).join('') :
                                '<p class="empty-message">You haven\'t created any posts yet.</p>'
                            }
                        </section>

                        <section class="profile-section">
                            <h2><i class="fas fa-heart"></i> Posts You've Liked</h2>
                            ${profileData.LikedPosts && profileData.LikedPosts.length ? 
                                profileData.LikedPosts.map(post => this.renderPost(post, true)).join('') :
                                '<p class="empty-message">You haven\'t liked any posts yet.</p>'
                            }
                        </section>
                    </div>
                </div>
            `;
        } catch (error) {
            store.setError('Failed to load profile data');
            console.error('Profile error:', error);
        } finally {
            store.setLoading(false);
        }
    }
}

// Create global reference
const profile = new Profile();
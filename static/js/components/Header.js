class Header {
    constructor() {
        this.container = document.getElementById('header-container');
        this.render();

        // Subscribe to user state changes
        store.subscribe((state) => {
            if (this.lastUserState !== state.user) {
                this.lastUserState = state.user;
                this.render();
            }
        });
    }

    render() {
        const user = store.state.user;
        this.container.innerHTML = `
            <div class="hamburger" onclick="header.toggleMenu()">
                <i class="fas fa-bars"></i>
            </div>
            <div class="logo">
                <a href="/" class="logo-link">Forum</a>
            </div>
            <nav>
            ${user ? `
                <a href="/profile" 
                   style="display: flex; align-items: center; gap: 8px; color: #4A76a8;">
                    <span class="welcome-text" style="font-size: 18px; margin-top: 10px;">Welcome, ${user.Nickname}</span>
                    <span class="material-icons" style="font-size: 30px; margin-top: 10px; vertical-align: middle;">person</span>                  
                </a>
                <a href="/create-post" class="auth-button create-post">
                    <span class="create-post-text">Create Post</span>
                    <span class="create-post-icon"><i class="fas fa-plus"></i></span>
                </a>
                <a href="#" class="logout-icon" title="Logout">
                    <i class="fas fa-sign-out-alt" style="font-size: 24px; color: #4A76a8; margin-top: 10px;"></i>
                </a>
                ` : `
                <a href="/register" class="auth-button register">Register</a>
                `}
            </nav>
        `;
        // Attach event handler for logout button
        const logoutBtn = this.container.querySelector('.logout-icon');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', this.handleLogout.bind(this));
        }
        // Attach event handler for create post button
        const createPostBtn = this.container.querySelector('.create-post');
        if (createPostBtn) {
            createPostBtn.addEventListener('click', (event) => {
                event.preventDefault();
                this.toggleCreatePost();
            });
        }
    }

    toggleMenu() {
        const sidebar = document.getElementById('sidebar-container');
        sidebar.style.display = sidebar.style.display === 'block' ? 'none' : 'block';
    }

    toggleCreatePost() {
        if (!store.state.user) {
            router.navigate('/login');
            return;
        }

        const mainContainer = document.getElementById('main-container');
        const currentForm = mainContainer.querySelector('.create-post-form');

        if (currentForm) {
            mainContainer.removeChild(currentForm);
            return;
        }

        router.navigate('/create-post');
    }

    async handleLogout(event) {
        event.preventDefault();
        try {
            store.setLoading(true);
            await api.logout(); // Using our fixed logout method

            // Update local state to reflect logged out status
            store.setUser(null);

            // Navigate to login page
            router.navigate('/login', true);
        } catch (error) {
            console.error('Logout error:', error);
            store.setError('Logout failed. Please try again.');
        } finally {
            store.setLoading(false);
        }
    }
}

// Create global reference for event handlers
const header = new Header();
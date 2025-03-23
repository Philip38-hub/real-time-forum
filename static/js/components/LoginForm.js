class LoginForm {
    constructor() {
        this.container = document.getElementById('main-container');
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-container">
                <h1>Login</h1>
                
                <!-- Google Sign-In Button -->
                <a href="/auth/google/login" class="google-btn">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google Logo">
                    <span>Sign in with Google</span>
                </a>

                <!-- GitHub Sign-In Button -->
                <a href="/auth/github/login" class="github-btn">
                    <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub Logo">
                    <span>Sign in with GitHub</span>
                </a>

                <div class="oauth-divider">
                    <span>or</span>
                </div>

                <!-- Traditional Login Form -->
                <form onsubmit="loginForm.handleSubmit(event)">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" placeholder="example@gmail.com" required>
                    <br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    <br>
                    <button type="submit">Login</button>
                </form>
                <p>Don't have an account? <a href="/register">Register here</a></p>
                <p class="home-link"><a href="/">← Back to Homepage</a></p>
            </div>
        `;

        // Add click handlers for OAuth buttons
        this.container.querySelector('.google-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/google/login';
        });

        this.container.querySelector('.github-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/github/login';
        });
    }

    async handleSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);

        try {
            store.setLoading(true);
            store.setError(null);

            const response = await api.login(
                formData.get('email'),
                formData.get('password')
            );

            if (response.success) {
                store.setUser(response.user);
                router.navigate('/', true);
            } else {
                store.setError(response.error || 'Login failed');
            }
        } catch (error) {
            store.setError('Login failed. Please try again.');
            console.error('Login error:', error);
        } finally {
            store.setLoading(false);
        }
    }
}

// Create global reference for event handlers
const loginForm = new LoginForm();
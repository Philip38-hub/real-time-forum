class LoginForm {
    constructor() {
        this.container = document.querySelector('.container'); // Updated to target the entire container
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-container">
                <h1>Login</h1>
                <div class="error-message" style="display: none;"></div>
                
                <!-- Commenting out social login buttons until they're active
                <a href="/auth/google/login" class="google-btn">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google Logo">
                    <span>Sign in with Google</span>
                </a>

                <a href="/auth/github/login" class="github-btn">
                    <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub Logo">
                    <span>Sign in with GitHub</span>
                </a>

                <div class="oauth-divider">
                    <span>or</span>
                </div>
                -->

                <!-- Traditional Login Form -->
                <form onsubmit="loginForm.handleSubmit(event)">
                    <label for="identifier">Email or Nickname:</label>
                    <input type="text" id="identifier" name="identifier" placeholder="Email or Nickname" required>
                    <br>
                    <label for="password">Password:</label>
                    <div class="password-input-wrapper">
                        <input type="password" id="password" name="password" required>
                        <button type="button" class="toggle-password" style="width: 2.5rem;" aria-label="Show password">
                            <i class="far fa-eye"></i>
                        </button>
                    </div>
                    <br>
                    <button type="submit">Login</button>
                </form>
                <p>Don't have an account? <a href="/register">Register here</a></p>
            </div>
        `;

        // Add toggle password visibility functionality
        const toggleButton = this.container.querySelector('.toggle-password');
        toggleButton.addEventListener('click', (e) => {
            const passwordInput = e.target.closest('.password-input-wrapper').querySelector('input');
            const icon = e.target.tagName === 'I' ? e.target : e.target.querySelector('i');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });

        /* Commenting out OAuth button handlers until they're active
        // Add click handlers for OAuth buttons
        this.container.querySelector('.google-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/google/login';
        });

        this.container.querySelector('.github-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/github/login';
        });
        */
    }

    showError(message) {
        const errorMessageDiv = this.container.querySelector('.error-message');
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
    }

    clearError() {
        const errorMessageDiv = this.container.querySelector('.error-message');
        errorMessageDiv.textContent = '';
        errorMessageDiv.style.display = 'none';
    }

    async handleSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);

        try {
            store.setLoading(true);
            this.clearError();

            const response = await api.login(
                formData.get('identifier'),
                formData.get('password')
            );

            if (response.success) {
                document.querySelector('.container').innerHTML = '';
                await new Promise(resolve => {
                    router.navigate('/', true);
                    setTimeout(resolve, 100);
                });
            }
        } catch (error) {
            this.showError('Login failed. Invalid credentials.');
        } finally {
            store.setLoading(false);
        }
    }
}

// Create global reference for event handlers
const loginForm = new LoginForm();

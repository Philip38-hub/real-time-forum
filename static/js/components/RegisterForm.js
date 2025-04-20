class RegisterForm {
    constructor() {
        this.container = document.querySelector('.container'); // Updated to target the entire container
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-container">
                <h1>Register</h1>

                <!-- Google Sign-In Button -->
                <a href="/auth/google/login" class="google-btn">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google Logo">
                    <span>Sign up with Google</span>
                </a>

                <!-- GitHub Sign-In Button -->
                <a href="/auth/github/login" class="github-btn">
                    <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub Logo">
                    <span>Sign up with GitHub</span>
                </a>

                <div class="oauth-divider">
                    <span>or</span>
                </div>

                <!-- Traditional Registration Form -->
                <form onsubmit="registerForm.handleSubmit(event)">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" placeholder="example@gmail.com" required>
                    <br>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                    <br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    <br>
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                    <br>
                    <button type="submit">Register</button>
                </form>
                <p>Already have an account? <a href="/login">Login here</a></p>
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

    validateForm(email, username, password, confirmPassword) {
        if (!email || !username || !password || !confirmPassword) {
            store.setError('All fields are required');
            return false;
        }

        if (password !== confirmPassword) {
            store.setError('Passwords do not match');
            return false;
        }

        if (password.length < 6) {
            store.setError('Password must be at least 6 characters long');
            return false;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            store.setError('Please enter a valid email address');
            return false;
        }

        return true;
    }

    async handleSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);

        const email = formData.get('email');
        const username = formData.get('username');
        const password = formData.get('password');
        const confirmPassword = formData.get('confirm_password');

        if (!this.validateForm(email, username, password, confirmPassword)) {
            return;
        }

        try {
            store.setLoading(true);
            store.setError(null);

            const response = await api.register(
                username,
                email,
                password
            );

            if (response.success) {
                store.setUser(response.user);
                router.navigate('/', true);
            } else {
                store.setError(response.error || 'Registration failed');
            }
        } catch (error) {
            store.setError('Registration failed. Please try again.');
            console.error('Registration error:', error);
        } finally {
            store.setLoading(false);
        }
    }
}

// Create global reference for event handlers
const registerForm = new RegisterForm();
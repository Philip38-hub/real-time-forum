class RegisterForm {
    constructor() {
        this.container = document.querySelector('.container');
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-container">
                <h1>Register</h1>
                <div class="error-message" style="display: none;"></div>
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

                <!-- Registration Form -->
                <form onsubmit="registerForm.handleSubmit(event)">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="first_name">First Name:</label>
                            <input type="text" id="first_name" name="first_name" required>
                        </div>
                        <div class="form-group">
                            <label for="last_name">Last Name:</label>
                            <input type="text" id="last_name" name="last_name" required>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="age">Age:</label>
                            <input type="number" id="age" name="age" min="13" required>
                        </div>
                        <div class="form-group">
                            <label for="gender">Gender:</label>
                            <select id="gender" name="gender" required>
                                <option value="">Select Gender</option>
                                <option value="male">Male</option>
                                <option value="female">Female</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" placeholder="example@gmail.com" required>
                    </div>

                    <div class="form-group">
                        <label for="nickname">Nickname:</label>
                        <input type="text" id="nickname" name="nickname" required>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <div class="form-group">
                            <label for="confirm_password">Confirm Password:</label>
                            <input type="password" id="confirm_password" name="confirm_password" required>
                        </div>
                    </div>

                    <button type="submit" class="btn-primary">Register</button>
                </form>
                <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
        `;

        // Add OAuth button handlers
        this.container.querySelector('.google-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/google/login';
        });

        this.container.querySelector('.github-btn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/auth/github/login';
        });
    }

    validateForm(formData) {
        const {
            first_name,
            last_name,
            age,
            gender,
            email,
            nickname,
            password,
            confirm_password
        } = formData;

        // Check required fields
        if (!first_name || !last_name || !age || !gender || !email || !nickname || !password || !confirm_password) {
            this.showError('All fields are required');
            return false;
        }

        // Validate age
        if (age < 13) {
            this.showError('You must be at least 13 years old to register');
            return false;
        }

        // Validate gender
        if (!['male', 'female'].includes(gender)) {
            this.showError('Please select a valid gender');
            return false;
        }

        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            this.showError('Please enter a valid email address');
            return false;
        }

        // Validate password
        if (password.length < 6) {
            this.showError('Password must be at least 6 characters long');
            return false;
        }

        if (password !== confirm_password) {
            this.showError('Passwords do not match');
            return false;
        }

        return true;
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

        const registrationData = {
            first_name: formData.get('first_name'),
            last_name: formData.get('last_name'),
            age: parseInt(formData.get('age')),
            gender: formData.get('gender'),
            email: formData.get('email'),
            nickname: formData.get('nickname'),
            password: formData.get('password'),
            confirm_password: formData.get('confirm_password')
        };

        if (!this.validateForm(registrationData)) {
            return;
        }

        try {
            store.setLoading(true);
            this.clearError();
            store.setError(null);

            // Remove confirm_password before sending to API
            delete registrationData.confirm_password;

            const response = await api.register(registrationData);

            if (response.success) {
                store.setUser(response.user);
                router.navigate('/', true);
            }
        } catch (error) {
            this.showError('Registration failed. Please try again.');
        } finally {
            store.setLoading(false);
        }
    }
}

const registerForm = new RegisterForm();
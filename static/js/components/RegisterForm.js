class RegisterForm {
    constructor() {
        this.container = document.querySelector('.container');
        this.usernameRegex = /^[a-zA-Z][a-zA-Z0-9._-]{2,29}$/; // Username validation pattern
        this.emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/; // Email validation pattern
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-container">
                <h1>Register</h1>
                <div class="error-message" style="display: none;"></div>
                
                <!-- Commenting out social login buttons until they're active
                <a href="/auth/google/login" class="google-btn">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google Logo">
                    <span>Sign up with Google</span>
                </a>

                <a href="/auth/github/login" class="github-btn">
                    <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub Logo">
                    <span>Sign up with GitHub</span>
                </a>

                <div class="oauth-divider">
                    <span>or</span>
                </div>
                -->

                <!-- Registration Form -->
                <form onsubmit="registerForm.handleSubmit(event)">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="first_name">First Name</label>
                            <input type="text" id="first_name" name="first_name" placeholder="Enter first name" required>
                        </div>
                        <div class="form-group">
                            <label for="last_name">Last Name</label>
                            <input type="text" id="last_name" name="last_name" placeholder="Enter last name" required>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="age">Age</label>
                            <input type="number" id="age" name="age" min="13" placeholder="Your age" required>
                        </div>
                        <div class="form-group">
                            <label for="gender">Gender</label>
                            <div class="select-wrapper">
                                <select id="gender" name="gender" required>
                                    <option value="">Select Gender</option>
                                    <option value="male">Male</option>
                                    <option value="female">Female</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" placeholder="example@gmail.com" required>
                        <div id="email-feedback" class="feedback-message"></div>
                    </div>

                    <div class="form-group">
                        <label for="nickname">Nickname</label>
                        <input type="text" id="nickname" name="nickname" placeholder="Choose a nickname" required>
                        <div id="nickname-feedback" class="feedback-message"></div>
                        <div class="form-hint">
                            Start with a letter, 3-30 characters, alphanumeric with ._- (no @ symbols)
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="password">Password</label>
                            <div class="password-input-wrapper">
                                <input type="password" id="password" name="password" required minlength="8" placeholder="Min. 8 characters">
                                <button type="button" class="toggle-password" style="width: 2.5rem;" aria-label="Show password">
                                    <i class="far fa-eye"></i>
                                </button>
                            </div>
                            <div class="password-strength-wrapper">
                                <div id="password-strength" class="password-strength"></div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="confirm_password">Confirm Password</label>
                            <div class="password-input-wrapper">
                                <input type="password" id="confirm_password" name="confirm_password" required placeholder="Re-enter password">
                                <button type="button" class="toggle-password" style="width: 2.5rem;" aria-label="Show password">
                                    <i class="far fa-eye"></i>
                                </button>
                            </div>
                            <div id="password-match" class="feedback-message"></div>
                        </div>
                    </div>

                    <button type="submit" class="btn-primary">Create Account</button>
                </form>
                <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
        `;

        // Add event listeners for real-time validation
        this.container.querySelector('#nickname').addEventListener('input', (e) => this.validateNickname(e.target));
        this.container.querySelector('#email').addEventListener('input', (e) => this.validateEmail(e.target));
        this.container.querySelector('#password').addEventListener('input', (e) => {
            this.validatePasswordStrength(e.target);
            this.validatePasswordMatch();
        });
        this.container.querySelector('#confirm_password').addEventListener('input', () => this.validatePasswordMatch());

        // Toggle password visibility
        const toggleButtons = this.container.querySelectorAll('.toggle-password');
        toggleButtons.forEach(button => {
            button.addEventListener('click', (e) => {
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
        });

        /* Commenting out OAuth button handlers until they're active
        // Add OAuth button handlers
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

    validateNickname(input) {
        const nickname = input.value.trim();
        const feedbackElement = document.getElementById('nickname-feedback');

        // Clear previous feedback
        feedbackElement.textContent = '';
        feedbackElement.className = 'feedback-message';

        if (!nickname) {
            return;
        }

        // Check if contains @ symbol
        if (nickname.includes('@')) {
            feedbackElement.textContent = 'Nickname cannot contain @ symbol';
            feedbackElement.className = 'feedback-message error';
            input.setCustomValidity('Username cannot contain @ symbol');
            return;
        }

        // Check regex pattern
        if (!this.usernameRegex.test(nickname)) {
            feedbackElement.textContent = 'Invalid nickname format';
            feedbackElement.className = 'feedback-message error';
            input.setCustomValidity('Invalid username format');
            return;
        }

        // If we got here, the format is valid
        feedbackElement.textContent = 'Nickname is available';
        feedbackElement.className = 'feedback-message success';
        input.setCustomValidity('');
    }

    validateEmail(input) {
        const email = input.value.trim();
        const feedbackElement = document.getElementById('email-feedback');

        // Clear previous feedback
        feedbackElement.textContent = '';
        feedbackElement.className = 'feedback-message';

        if (!email) {
            return;
        }

        if (!this.emailRegex.test(email)) {
            feedbackElement.textContent = 'Please enter a valid email address';
            feedbackElement.className = 'feedback-message error';
            input.setCustomValidity('Invalid email format');
        } else {
            feedbackElement.textContent = 'Email format is valid';
            feedbackElement.className = 'feedback-message success';
            input.setCustomValidity('');
        }
    }

    validatePasswordStrength(input) {
        const password = input.value;
        const strengthDiv = document.getElementById('password-strength');

        // Clear previous feedback
        strengthDiv.textContent = '';
        strengthDiv.className = 'password-strength';

        if (!password) {
            return;
        }

        // Check minimum length
        if (password.length < 8) {
            strengthDiv.textContent = 'Password is too short (minimum 8 characters)';
            strengthDiv.className = 'password-strength weak';
            input.setCustomValidity('Password must be at least 8 characters');
            return;
        }

        // Check strength
        let strength = 0;
        if (password.match(/[a-z]+/)) strength += 1;
        if (password.match(/[A-Z]+/)) strength += 1;
        if (password.match(/[0-9]+/)) strength += 1;
        if (password.match(/[^a-zA-Z0-9]+/)) strength += 1;

        if (strength < 2) {
            strengthDiv.textContent = 'Weak password';
            strengthDiv.className = 'password-strength weak';
        } else if (strength < 4) {
            strengthDiv.textContent = 'Moderate password';
            strengthDiv.className = 'password-strength moderate';
        } else {
            strengthDiv.textContent = 'Strong password';
            strengthDiv.className = 'password-strength strong';
        }

        input.setCustomValidity('');
    }

    validatePasswordMatch() {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password');
        const matchDiv = document.getElementById('password-match');

        // Clear previous feedback
        matchDiv.textContent = '';
        matchDiv.className = 'feedback-message';

        if (!confirmPassword.value) {
            return;
        }

        if (password !== confirmPassword.value) {
            matchDiv.textContent = 'Passwords do not match';
            matchDiv.className = 'feedback-message error';
            confirmPassword.setCustomValidity('Passwords do not match');
        } else {
            matchDiv.textContent = 'Passwords match';
            matchDiv.className = 'feedback-message success';
            confirmPassword.setCustomValidity('');
        }
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
        if (!this.emailRegex.test(email)) {
            this.showError('Please enter a valid email address');
            return false;
        }

        // Validate nickname
        if (!this.usernameRegex.test(nickname)) {
            this.showError('Invalid username format. Username must start with a letter and contain only letters, numbers, underscores, periods, and hyphens.');
            return false;
        }

        // Check for @ in nickname
        if (nickname.includes('@')) {
            this.showError('Username cannot contain @ symbol');
            return false;
        }

        // Validate password
        if (password.length < 8) {
            this.showError('Password must be at least 8 characters long');
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

        // Scroll to the error message
        errorMessageDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
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
            first_name: formData.get('first_name').trim(),
            last_name: formData.get('last_name').trim(),
            age: parseInt(formData.get('age')),
            gender: formData.get('gender'),
            email: formData.get('email').trim(),
            nickname: formData.get('nickname').trim(),
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

            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(registrationData),
                credentials: 'include'
            });

            const data = await response.json();

            if (!response.ok) {
                if (response.status === 409) {
                    // Check if error message contains specific keywords
                    const errorMsg = data.error || data.message || data.errorMessage || '';
                    if (errorMsg.toLowerCase().includes('email')) {
                        this.showError('Email already registered. Please use a different email address.');
                    } else if (errorMsg.toLowerCase().includes('username') ||
                        errorMsg.toLowerCase().includes('nickname')) {
                        this.showError('Username already taken. Please choose a different username.');
                    } else {
                        this.showError('Registration failed. A user with this email or username already exists.');
                    }
                } else {
                    this.showError(data.error || 'Registration failed. Please try again.');
                }
                return;
            }

            // Success case
            this.container.innerHTML = `
                <div class="success-container">
                    <svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
                        <circle class="checkmark-circle" cx="26" cy="26" r="25" fill="none"/>
                        <path class="checkmark-check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8"/>
                    </svg>
                    <h2>Registration Successful!</h2>
                    <p>Welcome ${registrationData.first_name}! Your account has been created.</p>
                    <p>You will be redirected to the login page shortly...</p>
                </div>
            `;

            // Redirect after a short delay
            setTimeout(() => {
                router.navigate('/login', true);
            }, 2000);
        } catch (error) {
            console.error('Registration error:', error);
            this.showError('Registration failed. Please try again.');
        } finally {
            store.setLoading(false);
        }
    }
}

const registerForm = new RegisterForm();

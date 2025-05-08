class ErrorPage {
    constructor() {
        // Find our containers
        this.mainContainer = document.querySelector('.container');
        this.errorContainer = document.getElementById('error-page-container');

        console.log('ErrorPage component initialized');
    }

    render(options = {}) {
        console.log('ErrorPage.render called with options:', options);

        const {
            statusCode = 404,
            title = 'Page Not Found',
            message = 'The page you are looking for does not exist or has been moved.',
            helpText = 'Please check the URL or go back to the homepage.',
            showHomeButton = true
        } = options;

        // Critical: Hide the main container and show error container
        if (this.mainContainer) {
            this.mainContainer.style.display = 'none';
        }

        // Make sure the error container is visible
        if (this.errorContainer) {
            this.errorContainer.style.display = 'block';
            this.container = this.errorContainer; // Set active container
        } else {
            // Error container doesn't exist, create one
            this.errorContainer = document.createElement('div');
            this.errorContainer.id = 'error-page-container';
            document.body.appendChild(this.errorContainer);
            this.container = this.errorContainer;
        }

        // Render the error content
        this.container.innerHTML = `
            <div class="error-page">
                <div class="error-container">
                    <div class="error-icon">
                        <i class="fas ${statusCode === 404 ? 'fa-map-signs' : 'fa-exclamation-triangle'}"></i>
                    </div>
                    <h1 class="error-code">${statusCode}</h1>
                    <h2 class="error-title">${title}</h2>
                    <p class="error-message">${message}</p>
                    <p class="error-help">${helpText}</p>
                    ${showHomeButton ? `
                        <a href="/" class="back-button" id="go-home">
                            <i class="fas fa-home"></i> Go to Homepage
                        </a>
                    ` : ''}
                </div>
            </div>
        `;

        // Add event listener for the home button
        const homeButton = document.getElementById('go-home');
        if (homeButton) {
            homeButton.addEventListener('click', (e) => {
                e.preventDefault();
                // When going home, restore the normal view
                this.hideErrorPage();
                router.navigate('/', true);
            });
        }
    }

    // New method to hide error page and restore main content
    hideErrorPage() {
        if (this.errorContainer) {
            this.errorContainer.style.display = 'none';
        }
        if (this.mainContainer) {
            this.mainContainer.style.display = '';
        }
    }
}

// Create global reference
const errorPage = new ErrorPage();
console.log('ErrorPage global reference created');
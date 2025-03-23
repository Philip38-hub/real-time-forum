class App {
    constructor() {
        // Initialize core components
        this.header = new Header();
        this.sidebar = new Sidebar();

        // Initialize router
        router.init();

        // Add loading indicator
        this.setupLoadingIndicator();

        // Add error handling
        this.setupErrorHandling();

        // Check user session
        this.checkSession();
    }

    setupLoadingIndicator() {
        // Create loading indicator element
        const loadingIndicator = document.createElement('div');
        loadingIndicator.className = 'loading-indicator';
        loadingIndicator.style.display = 'none';
        document.body.appendChild(loadingIndicator);

        // Subscribe to loading state changes
        store.subscribe((state) => {
            loadingIndicator.style.display = state.isLoading ? 'block' : 'none';
        });
    }

    setupErrorHandling() {
        // Create error toast element
        const errorToast = document.createElement('div');
        errorToast.className = 'error-toast';
        errorToast.style.display = 'none';
        document.body.appendChild(errorToast);

        // Subscribe to error state changes
        store.subscribe((state) => {
            if (state.error) {
                errorToast.textContent = state.error;
                errorToast.style.display = 'block';
                setTimeout(() => {
                    errorToast.style.display = 'none';
                    store.setError(null);
                }, 3000);
            }
        });
    }

    async checkSession() {
        try {
            store.setLoading(true);
            await api.checkSession();
        } catch (error) {
            console.error('Session check failed:', error);
        } finally {
            store.setLoading(false);
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new App();
});
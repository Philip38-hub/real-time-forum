class App {
    constructor() {
        // Initialize core components
        this.header = new Header();
        this.sidebar = new Sidebar();

        // Add loading indicator
        this.setupLoadingIndicator();

        // Add error handling
        this.setupErrorHandling();

        // Start session check and router initialization
        this.initializeApp();
    }

    async initializeApp() {
        // Initialize router immediately but don't handle routes yet
        router.init();
        
        // Check session in background
        this.checkSession().catch(error => {
            console.error('Session check failed:', error);
        });
        
        // Handle initial route after everything is set up
        router.handleRoute();
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
            const currentPath = window.location.pathname;
            store.setLoading(true);
            const isLoggedIn = await api.checkSession();
            
            // Only redirect if on a protected route and not logged in
            if (!isLoggedIn && currentPath !== '/' && currentPath !== '/login' && currentPath !== '/register') {
                router.navigate('/login', true);
            }
        } catch (error) {
            console.error('Session check failed:', error);
            // On error, only redirect if not on a public route
            const currentPath = window.location.pathname;
            if (currentPath !== '/' && currentPath !== '/login' && currentPath !== '/register') {
                router.navigate('/login', true);
            }
        } finally {
            store.setLoading(false);
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new App();
});
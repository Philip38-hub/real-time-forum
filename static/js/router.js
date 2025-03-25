class Router {
    constructor() {
        this.routes = [];
        this.notFoundHandler = () => {
            document.getElementById('main-container').innerHTML = '<h1>404 - Page Not Found</h1>';
        };

        // Handle browser navigation events
        window.addEventListener('popstate', () => this.handleRoute());
        
        // Intercept link clicks for client-side routing
        document.addEventListener('click', (e) => {
            if (e.target.matches('a[href^="/"]')) {
                e.preventDefault();
                this.navigate(e.target.href);
            }
        });
    }

    addRoute(path, handler, options = {}) {
        // Convert path pattern to regex for matching
        const pattern = path
            .replace(/:\w+/g, '([^/]+)') // Convert :param to capture group
            .replace(/\*/g, '.*'); // Convert * to match anything
        
        this.routes.push({
            pattern: new RegExp(`^${pattern}$`),
            handler,
            authRequired: options.authRequired || false
        });
    }

    navigate(url, replace = false) {
        const path = new URL(url, window.location.origin).pathname;
        
        // Prevent recursive navigation to the same path
        if (path === window.location.pathname) {
            return;
        }
        
        // Update browser history
        if (replace) {
            window.history.replaceState(null, '', path);
        } else {
            window.history.pushState(null, '', path);
        }
        
        this.handleRoute();
    }

    async handleRoute() {
        const path = window.location.pathname;
        
        // Find matching route
        const route = this.routes.find(route => route.pattern.test(path));
        
        if (!route) {
            this.notFoundHandler();
            return;
        }

        // Check authentication if required
        if (route.authRequired && !store.state.user) {
            window.history.replaceState(null, '', '/login');
            const loginRoute = this.routes.find(r => r.pattern.test('/login'));
            if (loginRoute) {
                await loginRoute.handler();
            }
            return;
        }

        // Extract params from URL
        const params = path.match(route.pattern).slice(1);
        
        try {
            // Execute route handler
            await route.handler(...params);
        } catch (error) {
            console.error('Route handler error:', error);
            store.setError('An error occurred while loading the page');
        }
    }

    setNotFoundHandler(handler) {
        this.notFoundHandler = handler;
    }

    // Helper method to initialize routes
    init() {
        // Home page
        this.addRoute('/', async () => {
            store.setLoading(true);
            try {
                const posts = await api.getPosts();
                store.setPosts(posts);
                new PostList().render();
            } catch (error) {
                store.setError('Failed to load posts');
            } finally {
                store.setLoading(false);
            }
        }, { authRequired: false });

        // Login page
        this.addRoute('/login', () => {
            if (store.state.user) {
                this.navigate('/', true);
                return;
            }
            const loginForm = new LoginForm();
            loginForm.render();
        }, { authRequired: false });

        // Register page
        this.addRoute('/register', () => {
            if (store.state.user) {
                this.navigate('/', true);
                return;
            }
            const registerForm = new RegisterForm();
            registerForm.render();
        }, { authRequired: false });

        // Profile page
        this.addRoute('/profile', () => {
            if (!store.state.user) {
                this.navigate('/login', true);
                return;
            }
            const profile = new Profile();
            profile.render();
        }, { authRequired: true });

        // Category filter
        this.addRoute('/filter', async () => {
            const params = new URLSearchParams(window.location.search);
            const category = params.get('category');
            
            if (!category) {
                this.navigate('/', true);
                return;
            }

            store.setLoading(true);
            try {
                const posts = await api.getPostsByCategory(category);
                store.setPosts(posts);
                new PostList().render();
            } catch (error) {
                store.setError('Failed to load posts');
            } finally {
                store.setLoading(false);
            }
        }, { authRequired: false });
        
        // Routes are now initialized but handleRoute() will be called by App
    }
}

// Create and export a single router instance
const router = new Router();
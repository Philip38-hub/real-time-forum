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
            // For authenticated routes, ensure state is ready
            if (route.authRequired) {
                // Wait for next tick to ensure state updates are processed
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
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
                // Clear and setup container first to avoid any leftover content
                const container = document.querySelector('.container');
                container.innerHTML = '';
                
                // Setup fresh container structure
                container.innerHTML = `
                    <aside class="sidebar" id="sidebar-container"></aside>
                    <main id="main-container"></main>
                `;

                // Render sidebar first
                const sidebar = new Sidebar();
                sidebar.render();

                try {
                    // Load posts
                    const posts = await api.getPosts();

                    if (!Array.isArray(posts)) {
                        throw new Error('Invalid posts data received');
                    }
                    if (posts.length > 0) {
                        await store.setPosts(posts);
                        await new Promise(resolve => setTimeout(resolve, 0));

                        // Create and render PostList
                        const main = document.getElementById('main-container');
                        const postList = new PostList();
                        postList.render();
                    }
                } catch (error) {
                    console.error('Failed to load posts:', error);
                    document.getElementById('main-container').innerHTML = `
                        <div class="error-message">
                            <p>Failed to load posts. Please try again.</p>
                            <p>Error: ${error.message}</p>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Route error:', error);
                store.setError('An error occurred while loading the page');
            } finally {
                store.setLoading(false);
            }
        }, { authRequired: true });

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

        // Create Post page
        this.addRoute('/create-post', () => {
            const main = document.getElementById('main-container');
            if (main) {
                main.innerHTML = '';
            }
            const postForm = new PostForm();
            postForm.render();
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
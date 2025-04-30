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
        const urlObj = new URL(url, window.location.origin);
        const fullPath = urlObj.pathname + urlObj.search + urlObj.hash;

        // Prevent recursive navigation to the same path
        if (fullPath === window.location.pathname + window.location.search + window.location.hash) {
            return;
        }

        if (replace) {
            window.history.replaceState(null, '', fullPath);
        } else {
            window.history.pushState(null, '', fullPath);
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

    // Helper to setup main container and sidebar for most pages
    setupContainer() {
        const container = document.querySelector('.container');
        if (!container) return;
        container.innerHTML = `
            <aside class="sidebar" id="sidebar-container"></aside>
            <main id="main-container"></main>
            <div id="chat-container"></div>
        `;
        const sidebar = new Sidebar();
        sidebar.render();
        chat.render();
    }

    // Helper method to initialize routes
    init() {
        // Home page
        this.addRoute('/', async () => {
            this.setupContainer();
            store.setLoading(true);
            try {
                try {
                    // Load posts
                    const posts = await api.getPosts();
                    if (!Array.isArray(posts)) {
                        throw new Error('Invalid posts data received');
                    }
                    await store.setPosts(posts); 
                    // Create and render PostList
                    const postList = new PostList();
                    postList.render();
                } catch (error) {
                    console.error('Failed to load posts:', error);
                    document.getElementById('main-container').innerHTML = '<p>Failed to load posts. Please try again.</p>';
                }
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
        this.addRoute('/profile', async () => {
            const container = document.querySelector('.container');
            if (container) {
                container.innerHTML = '<main id="main-container"></main>';
            }
            const profile = new Profile();
            profile.render();
        }, { authRequired: true });

        // Create Post page
        this.addRoute('/create-post', () => {
            this.setupContainer();
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
        
    }
}

// Create and export a single router instance
const router = new Router();
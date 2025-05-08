class Router {
    constructor() {
        this.routes = [];
        this.notFoundHandler = () => {
            const options = {
                statusCode: 404,
                title: 'Page Not Found',
                message: 'The page you are looking for does not exist or has been moved.',
                helpText: 'Please check the URL or go back to the homepage.'
            };
            errorPage.render(options);
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
        try {
            const path = window.location.pathname;
            console.log('Router handling path:', path);

            // Special case for error route
            if (path === '/error') {
                console.log('Detected error route, rendering error page');
                // Make sure the error page is shown and main content is hidden
                const errorRoute = this.routes.find(route => route.pattern.test('/error'));
                if (errorRoute) {
                    await errorRoute.handler();
                    return;
                }
            } else {
                // For non-error routes, make sure to hide the error page
                if (window.errorPage) {
                    errorPage.hideErrorPage();
                }
            }

            // Find matching route
            const route = this.routes.find(route => route.pattern.test(path));

            if (!route) {
                console.log('No route found for path:', path);
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

            // Ensure store and auth state is ready
            await new Promise(resolve => setTimeout(resolve, 0));

            // Execute route handler
            try {
                store.setLoading(true);
                await route.handler(...params);
            } catch (error) {
                console.error('Route handler error:', error);
                errorPage.render({
                    statusCode: 500,
                    title: 'Internal Error',
                    message: 'An error occurred while loading the page',
                    helpText: 'Please try again later or contact support if the problem persists.'
                });
            } finally {
                store.setLoading(false);
            }

        } catch (error) {
            console.error('Route handler error:', error);
            errorPage.render({
                statusCode: 500,
                title: 'Internal Error',
                message: 'An error occurred while loading the page',
                helpText: 'Please try again later or contact support if the problem persists.'
            });
        }
    }

    setNotFoundHandler(handler) {
        this.notFoundHandler = handler || (() => {
            errorPage.render({
                statusCode: 404,
                title: 'Page Not Found',
                message: 'The page you are looking for does not exist or has been moved.',
                helpText: 'Please check the URL or go back to the homepage.'
            });
        });
    }

    // Helper to setup main container and sidebar for most pages
    setupContainer() {
        console.log('Setting up container');
        const container = document.querySelector('.container');
        if (!container) {
            console.error('Container element not found!');
            return;
        }

        console.log('Container found, setting up layout');
        container.innerHTML = `
            <aside class="sidebar" id="sidebar-container"></aside>
            <main id="main-container"></main>
            <div id="chat-container"></div>
        `;

        // Update the reference in the ErrorPage component
        if (window.errorPage) {
            errorPage.container = document.getElementById('main-container');
            console.log('Updated errorPage.container:', errorPage.container);
        }

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
            this.setupContainer();
            const params = new URLSearchParams(window.location.search);
            const category = params.get('category');

            if (!category) {
                this.navigate('/', true);
                return;
            }

            store.setLoading(true);
            const main = document.getElementById('main-container');
            try {
                // First try to use stored posts
                const storedPosts = store.getCachedPosts(category);
                if (storedPosts && store.state.currentCategory === category) {
                    await store.setPosts(storedPosts, category);
                    new PostList().render();
                } else {
                    // If no stored posts, fetch from API
                    if (main) main.innerHTML = '<p>Loading posts...</p>';
                    const posts = await api.getPostsByCategory(category);
                    await store.setPosts(posts, category);
                    new PostList().render();
                }
            } catch (error) {
                console.error('Failed to load filtered posts:', error);
                if (main) {
                    main.innerHTML = '<p>Failed to load posts. Please try again.</p>';
                }
            } finally {
                store.setLoading(false);
            }
        }, { authRequired: true });

        // Error page
        this.addRoute('/error', () => {
            console.log('Error route handler executing');

            // Parse error parameters from URL
            const urlParams = new URLSearchParams(window.location.search);
            const statusCode = parseInt(urlParams.get('code') || '404');
            const message = urlParams.get('message') || 'An error occurred';
            const helpText = urlParams.get('help') || 'Please try again or contact support.';

            console.log('Rendering error page with:', { statusCode, message, helpText });

            // Render the error page
            errorPage.render({
                statusCode: statusCode,
                title: `Error ${statusCode}`,
                message: message,
                helpText: helpText
            });
        });

    }
}

// Create and export a single router instance
const router = new Router();

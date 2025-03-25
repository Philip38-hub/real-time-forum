class Sidebar {
    constructor() {
        this.container = document.getElementById('sidebar-container');
        this.categories = store.state.categories;
        this.render();

        // Subscribe to category changes
        store.subscribe((state) => {
            if (this.categories !== state.categories) {
                this.categories = state.categories;
                this.render();
            }
        });
    }

    getActiveCategory() {
        const params = new URLSearchParams(window.location.search);
        return params.get('category') || '';
    }

    render() {
        const activeCategory = this.getActiveCategory();
        
        this.container.innerHTML = `
                <h3>Categories</h3>
                <ul>
                    <li>
                        <a href="/" class="${!activeCategory ? 'active' : ''}">
                            All Posts
                        </a>
                    </li>
                    ${this.categories.map(category => `
                        <li>
                            <a href="/filter?category=${category}" 
                               class="${activeCategory === category ? 'active' : ''}">
                                ${category.charAt(0).toUpperCase() + category.slice(1)}
                            </a>
                        </li>
                    `).join('')}
                </ul>
        `;

        // Add click event listeners
        this.container.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const href = link.getAttribute('href');
                router.navigate(href);
                
                // Close sidebar on mobile after category selection
                if (window.innerWidth <= 768) {
                    this.container.style.display = 'none';
                }
            });
        });
    }
}

// Create global reference for event handlers
const sidebar = new Sidebar();
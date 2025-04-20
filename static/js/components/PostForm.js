class PostForm {
    constructor() {
        this.container = document.getElementById('main-container');
    }

    render() {
        const form = document.createElement('div');
        form.className = 'create-post-form';
        form.innerHTML = `
            <h1>Create a New Post</h1>
            <form onsubmit="postForm.handleSubmit(event)" enctype="multipart/form-data">
                <label for="title">Title:</label>
                <input type="text" id="title" name="title" required>
                <br>

                <label for="content">Content:</label>
                <textarea id="content" name="content" required></textarea>
                <br>

                <label for="image">Image:</label>
                <input type="file" id="image" name="image" accept="image/jpeg, image/png, image/gif">
                <br>

                <label for="category">Category:</label>
                <div id="category" name="category" class="checkbox-group">
                    ${store.state.categories.map(category => `
                        <label>
                            <input type="checkbox" name="category" value="${category}"> 
                            ${category.charAt(0).toUpperCase() + category.slice(1)}
                        </label>
                    `).join('')}
                </div>
                <br>

                <button type="submit">Post</button>
                <button type="button" onclick="postForm.handleCancel()">Cancel</button>
            </form>
        `;

        // Insert form at the top of main container
        if (this.container.firstChild) {
            this.container.insertBefore(form, this.container.firstChild);
        } else {
            this.container.appendChild(form);
        }

        // Hide the posts section
        const posts = document.getElementById('posts');
        const postsHeading = document.getElementById('postsHeading');
        if (posts) posts.style.display = 'none';
        if (postsHeading) postsHeading.style.display = 'none';
    }

    async handleSubmit(event) {
        event.preventDefault();

        // Validate categories
        const selectedCategories = Array.from(
            event.target.querySelectorAll('input[name="category"]:checked')
        ).map(cb => cb.value);

        if (selectedCategories.length === 0) {
            store.setError('Please select at least one category');
            return;
        }

        // Create FormData
        const formData = new FormData(event.target);

        try {
            store.setLoading(true);
            const response = await api.createPost(formData);
            
            // Add the new post to the store
            if (response.post) {
                store.addPost(response.post);
            }

            // Hide form and show posts
            this.handleCancel();
            
            // Navigate to home page
            router.navigate('/', true);
        } catch (error) {
            store.setError('Failed to create post. Please try again.');
        } finally {
            store.setLoading(false);
        }
    }

    handleCancel() {
        // Remove the form
        const form = document.querySelector('.create-post-form');
        if (form) {
            form.remove();
        }
        console.log('Navigating to home page');
        router.navigate('/', true);
    }
}

// Create global reference for event handlers
const postForm = new PostForm();
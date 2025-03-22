/**
 Utility functions for the forum app
 */

// Toggle visibility of an element
function toggleElement(element) {
    if (element) {
        element.classList.toggle('hidden');
    }
}

// Show an element
function showElement(element) {
    if (element) {
        element.classList.remove('hidden');
    }
}

// Hide an element
function hideElement(element) {
    if (element) {
        element.classList.add('hidden');
    }
}

// Validate that a form has non-empty content
function validateFormContent(form) {
    const textarea = form.querySelector('textarea[name="content"]');
    if (!textarea || !textarea.value.trim()) {
        alert("Content cannot be empty. Please write something before submitting.");
        if (textarea) textarea.focus();
        return false;
    }
    return true;
}

// Validate that at least one category is selected
function validateCategories() {
    const checkboxes = document.querySelectorAll('input[name="category"]');
    let isChecked = false;

    checkboxes.forEach((checkbox) => {
        if (checkbox.checked) {
            isChecked = true;
        }
    });

    if (!isChecked) {
        alert("Please select at least one category.");
        return false;
    }
    return true;
}

// Get the display name for logging
function getLogPrefix() {
    return `[Forum ${new Date().toISOString()}]:`;
}

// Enhanced console logging
const logger = {
    log: (message, ...args) => console.log(getLogPrefix(), message, ...args),
    error: (message, ...args) => console.error(getLogPrefix(), message, ...args),
    warn: (message, ...args) => console.warn(getLogPrefix(), message, ...args),
    info: (message, ...args) => console.info(getLogPrefix(), message, ...args)
};

// Find parent element with a specific selector
function findParent(element, selector) {
    while (element && !element.matches(selector)) {
        element = element.parentElement;
    }
    return element;
}

// Get ID from a data attribute
function getIdFromElement(element, attribute) {
    return element ? element.getAttribute(attribute) : null;
}

// Create HTML element from string
function createElementFromHTML(htmlString) {
    const div = document.createElement('div');
    div.innerHTML = htmlString.trim();
    return div.firstChild;
}

// Debounce function to prevent rapid multiple clicks
function debounce(func, wait = 300) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Throttle function to limit how often a function can be called
function throttle(func, limit = 300) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}
// WebSocket Manager for forum real-time updates
class ForumWebSocket {
    constructor() {
        this.socket = null;
        this.connectionStatus = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Start with 1 second delay
        this.messageHandlers = {};
    }

    // Initialize the WebSocket connection
    init() {
        try {
            // Determine the correct WebSocket protocol based on the current page protocol
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const hostname = window.location.hostname;
            this.socket = new WebSocket(`${protocol}//${hostname}:8081/ws`);
            
            logger.info('WebSocket initialized with', `${protocol}//${hostname}:8081/ws`);
            this.setupEventHandlers();
        } catch (error) {
            logger.error('WebSocket initialization error:', error);
            this.scheduleReconnect();
        }
    }

    // Set up WebSocket event handlers
    setupEventHandlers() {
        this.socket.onopen = () => {
            logger.info('WebSocket connection established');
            this.connectionStatus = true;
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;
        };

        this.socket.onmessage = (event) => {
            try {
                logger.log('WebSocket message received:', event.data);
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                logger.error('Error processing WebSocket message:', error);
            }
        };

        this.socket.onclose = (event) => {
            this.connectionStatus = false;
            logger.warn(`WebSocket connection closed. Code: ${event.code}, Reason: ${event.reason}`);
            this.scheduleReconnect();
        };

        this.socket.onerror = (error) => {
            logger.error('WebSocket error:', error);
        };
    }

    // Register message handlers for different message types
    registerHandler(messageType, handler) {
        this.messageHandlers[messageType] = handler;
    }

    // Handle incoming WebSocket messages
    handleMessage(data) {
        // Check if there's a registered handler for this message type
        if (this.messageHandlers[data.type]) {
            this.messageHandlers[data.type](data.content);
            return;
        }

        // Default handlers if no specific handler registered
        switch (data.type) {
            case 'new_post':
                UI.addNewPost(data.content);
                break;
            case 'newComment':
                UI.addNewComment(data.content, false);
                break;
            case 'newReply':
                UI.addNewComment(data.content, true);
                break;
            case 'postLikeUpdate':
                UI.updateLikeUI(
                    document.querySelector(`[data-post-id='${data.content.target_id}']`),
                    data.content
                );
                break;
            case 'commentLikeUpdate':
                UI.updateLikeUI(
                    document.querySelector(`[data-comment-id='${data.content.target_id}']`),
                    data.content
                );
                break;
            default:
                logger.warn('Unknown WebSocket message type:', data.type);
        }
    }

    // Schedule a reconnection attempt with exponential backoff
    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

            logger.info(`Attempting to reconnect in ${delay / 1000} seconds...`);
            setTimeout(() => this.init(), delay);
        } else {
            logger.error(`Maximum reconnect attempts (${this.maxReconnectAttempts}) reached.`);
        }
    }

    // Send a message through WebSocket
    sendMessage(messageType, content) {
        if (!this.isConnected()) {
            logger.error('WebSocket is not connected');
            return false;
        }

        const message = {
            type: messageType,
            content: content,
        };

        try {
            this.socket.send(JSON.stringify(message));
            return true;
        } catch (error) {
            logger.error('Error sending WebSocket message:', error);
            return false;
        }
    }

    // Public method to check connection status
    isConnected() {
        return this.connectionStatus && this.socket && this.socket.readyState === WebSocket.OPEN;
    }
}

// Enhanced console logging
const getLogPrefix = () => {
    const now = new Date();
    return `[${now.toISOString()}] [WebSocket]`;
};

const logger = {
    log: (message, ...args) => console.log(getLogPrefix(), message, ...args),
    error: (message, ...args) => console.error(getLogPrefix(), message, ...args),
    warn: (message, ...args) => console.warn(getLogPrefix(), message, ...args),
    info: (message, ...args) => console.info(getLogPrefix(), message, ...args)
};

// Create singleton instance
const webSocketManager = new ForumWebSocket();
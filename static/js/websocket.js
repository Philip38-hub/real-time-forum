// ForumWebSocket communication for real-time updates
class ForumWebSocket {
    constructor() {
        this.socket = null;
        this.connectionStatus = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Start with 1 second delay
    }

    // Initialize the WebSocket connection
    init() {
        try {
            this.socket = new WebSocket("ws://localhost:8081/ws");
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

    // Handle incoming WebSocket messages
    handleMessage(data) {
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

    // Public method to check connection status
    isConnected() {
        return this.connectionStatus && this.socket && this.socket.readyState === WebSocket.OPEN;
    }
}

// Create singleton instance
const webSocketManager = new ForumWebSocket();
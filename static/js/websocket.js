// WebSocket Manager for forum real-time updates
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
            logger.info('WebSocket initialized');
            this.setupEventHandlers();
        } catch (error) {
            logger.error('WebSocket initialization error:', error);
            this.scheduleReconnect();
        }
    }
    connect() {
        const userId = localStorage.getItem('userId');
        const username = localStorage.getItem('username');

        console.log('Connecting WebSocket with:', { userId, username }); // Debug log

        if (!userId || !username) {
            console.error('Missing user data for WebSocket connection');
            return false;
        }

        this.socket = new WebSocket(`ws://${window.location.host}/ws`);
        this.setupEventHandlers();
        return true;
    }

    // Set up WebSocket event handlers
    setupEventHandlers() {
        this.socket.onopen = () => {
            console.log('WebSocket connected, sending auth...'); // Debug log

            const userId = localStorage.getItem('userId');
            const username = localStorage.getItem('username');

            console.log('WebSocket connection attempt:', {
                userId: userId,
                username: username,
                userIdType: typeof userId,
                usernameType: typeof username
            });

            if (!userId || !username) {
                console.error('Cannot establish WebSocket: Missing user data');
                return false;
            }

            const authData = {
                type: 'auth',
                userId: userId,
                username: username
            };

            console.log('Sending auth data:', authData); // Debug log
            this.socket.send(JSON.stringify(authData));

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

// Create singleton instance
const webSocketManager = new ForumWebSocket();
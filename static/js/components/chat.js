/**
 * Private messaging functionality
 */

class Chat {
    constructor() {
        this.currentUserId = null;
        this.currentNickname = null;
        this.currentChatUserId = null;
        this.typingTimeout = null;
        this.users = [];
        this.messages = {}; // Store messages by user ID
        this.unreadMessages = {}; // Track unread messages count
        this.page = 1;
        this.isLoadingMessages = false;
        this.hasMoreMessages = true;
        this.chatContainer = null;
        this.chatMain = null;
        this.usersList = null;
        this.chatMessages = null;
        this.chatForm = null;
        this.chatInput = null;
        this.chatUserName = null;
        this.chatUserStatus = null;
        this.userSearch = null;
        this.unreadCountElement = null;
        this.typingIndicator = null;
        this.chatToggle = null;
        this.backButton = null;
    }

    async initializeChat() {
        logger.info('Starting chat initialization...');
        try {
            const response = await fetch('/api/current-user', {
                credentials: 'include',
                headers: {
                    'Accept': 'application/json'
                }
            });
            logger.info('Profile fetch response status:', response.status);
            const data = await response.json();
            logger.info('Server response:', data);
            if (!response.ok || !data.authenticated) {
                throw new Error(data.error || `Authentication failed: ${response.status}`);
            }
            if (!data.userId || !data.nickname) {
                throw new Error('Invalid user info received');
            }
            this.currentUserId = data.userId;
            this.currentNickname = data.nickname;
            logger.info('User profile loaded:', {
                userId: this.currentUserId,
                nickname: this.currentNickname
            });
            this.init();
            return true;
        } catch (error) {
            logger.error('Error initializing chat:', error);
            return false;
        }
    }

    init() {
        this.initElements();
        this.fetchUsers();
        this.registerWebSocketHandlers();
        this.attachEventListeners();
        this.updateUnreadCount();
    }

    initElements() {
        this.chatContainer = document.getElementById('chat-container');
        this.chatMain = document.getElementById('chat-main');
        this.usersList = document.getElementById('users-list');
        this.chatMessages = document.getElementById('chat-messages');
        this.chatForm = document.getElementById('chat-form');
        this.chatInput = document.getElementById('chat-input');
        this.chatUserName = document.getElementById('chat-user-name');
        this.chatUserStatus = document.getElementById('chat-user-status');
        this.userSearch = document.getElementById('user-search');
        this.unreadCountElement = document.getElementById('unread-count');
        this.typingIndicator = document.getElementById('typing-indicator');
        this.chatToggle = document.getElementById('chat-toggle');
        this.backButton = document.getElementById('back-button');
    }

    registerWebSocketHandlers() {
        webSocketManager.registerHandler('privateMessage', (content) => {
            if (content.receiverId === this.currentUserId || content.senderId === this.currentUserId) {
                this.handleIncomingMessage(content);
            }
        });

        webSocketManager.registerHandler('typingIndicator', (content) => {
            this.showTypingIndicator(content);
        });

        webSocketManager.registerHandler('readReceipt', (content) => {
            if (content.senderId === this.currentUserId) {
                this.markMessageAsRead(content);
            }
        });

        webSocketManager.registerHandler('userStatus', (content) => {
            this.updateUserStatus(content.userId, content.online);
        });

        webSocketManager.registerHandler('messageSent', (content) => {
            logger.info('Message delivered:', content.messageId);
        });
    }

    attachEventListeners() {
        if (this.chatToggle) {
            this.chatToggle.addEventListener('click', this.toggleChatContainer.bind(this));
        }

        if (this.chatForm) {
            this.chatForm.addEventListener('submit', this.handleMessageSubmit.bind(this));
        }

        if (this.chatInput) {
            this.chatInput.addEventListener('input', this.handleTyping.bind(this));
        }

        if (this.chatMessages) {
            this.chatMessages.addEventListener('scroll', Chat.throttle(() => this.handleScroll(), 500));
        }

        if (this.userSearch) {
            this.userSearch.addEventListener('input', Chat.debounce((e) => this.filterUsers(e.target.value), 300));
        }

        if (this.backButton) {
            this.backButton.addEventListener('click', this.goBackToUserList.bind(this));
        }
    }

    goBackToUserList() {
        if (this.chatContainer) {
            this.chatContainer.classList.remove('chat-active');
        }
        this.currentChatUserId = null;

        // Refresh the users list when going back
        this.fetchUsers();
    }

    async fetchUsers() {
        try {
            const response = await apiRequests.fetchUsers();
            if (response.success) {
                this.users = response.users;

                // Process user data from server data
                response.users.forEach(user => {
                    // Handle unread counts
                    if (user.unread > 0) {
                        this.unreadMessages[user.id] = user.unread;
                    }

                    // Store last message time from server in our local cache
                    if (user.lastMessageTime) {
                        if (!this.messages[user.id]) {
                            this.messages[user.id] = [];
                        }

                        // Store the server-provided timestamp for sorting purposes
                        this.messages[user.id].lastServerTime = new Date(user.lastMessageTime).getTime();
                    }
                });

                this.renderUsers();
                this.updateUnreadCount();
            } else {
                logger.error('Failed to fetch users:', response.message);
            }
        } catch (error) {
            logger.error('Error fetching users:', error);
        }
    }

    renderUsers() {
        if (!this.usersList) return;

        this.usersList.innerHTML = '';

        const filteredUsers = this.users.filter(user => user.id !== this.currentUserId);

        // Sort users: first by last message time, then alphabetically
        const sortedUsers = [...filteredUsers].sort((a, b) => {
            // First check if there are messages
            const aLastMessageTime = this.getLastMessageTime(a.id);
            const bLastMessageTime = this.getLastMessageTime(b.id);

            // If both have messages, sort by most recent
            if (aLastMessageTime && bLastMessageTime) {
                return bLastMessageTime - aLastMessageTime;
            }

            // If only one has messages, prioritize that one
            if (aLastMessageTime) return -1;
            if (bLastMessageTime) return 1;

            return a.nickname.localeCompare(b.nickname);
        });

        sortedUsers.forEach(user => {
            const userElement = document.createElement('li');
            userElement.className = 'user';
            userElement.dataset.userId = user.id;

            const hasUnread = this.unreadMessages[user.id] && this.unreadMessages[user.id] > 0;

            userElement.innerHTML = `
                <span class="user-status-indicator ${user.online ? 'online' : 'offline'}"></span>
                <span class="user-name">${user.nickname}</span>
                ${hasUnread ? `<span class="unread-indicator">${this.unreadMessages[user.id]}</span>` : ''}
            `;

            userElement.addEventListener('click', () => this.openChat(user));
            this.usersList.appendChild(userElement);
        });
    }

    filterUsers(searchTerm) {
        const items = this.usersList.querySelectorAll('li');
        const lowerSearchTerm = searchTerm.toLowerCase();

        items.forEach(item => {
            const nickname = item.querySelector('.user-name').textContent.toLowerCase();
            if (nickname.includes(lowerSearchTerm)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }

    async openChat(user) {
        this.currentChatUserId = user.id;

        if (this.chatContainer) {
            this.chatContainer.classList.add('chat-active');
        }

        if (this.chatUserName) this.chatUserName.textContent = user.nickname;
        if (this.chatUserStatus) {
            this.chatUserStatus.textContent = user.online ? 'Online' : 'Offline';
            this.chatUserStatus.className = `user-status ${user.online ? 'online' : 'offline'}`;
        }

        if (this.chatMessages) this.chatMessages.innerHTML = '';

        this.page = 1;
        this.hasMoreMessages = true;

        await this.loadMessages();

        if (this.unreadMessages[user.id] && this.unreadMessages[user.id] > 0) {
            webSocketManager.sendMessage('readReceipt', {
                readerId: this.currentUserId,
                senderId: user.id
            });

            this.markMessagesAsRead(user.id);
        }

        if (this.chatInput) this.chatInput.focus();
    }

    async loadMessages() {
        if (!this.currentChatUserId || this.isLoadingMessages || !this.hasMoreMessages) return;

        try {
            this.isLoadingMessages = true;
            logger.info('Loading messages page:', this.page);

            const loadingEl = document.createElement('div');
            loadingEl.className = 'loading-messages';
            loadingEl.textContent = 'Loading messages...';
            this.chatMessages.prepend(loadingEl);

            const response = await apiRequests.fetchMessages(this.currentChatUserId, this.page);

            loadingEl.remove();

            if (response.success) {
                const messages = response.messages || [];
                this.hasMoreMessages = messages.length === 10;

                if (!this.messages[this.currentChatUserId]) {
                    this.messages[this.currentChatUserId] = [];
                }

                if (this.page === 1) {
                    const reversedMessages = [...messages].reverse();
                    this.messages[this.currentChatUserId] = reversedMessages;
                    this.renderMessages(reversedMessages);
                } else {
                    const reversedMessages = [...messages].reverse();
                    this.messages[this.currentChatUserId] = [
                        ...reversedMessages,
                        ...this.messages[this.currentChatUserId]
                    ];
                    this.renderMessages(reversedMessages, true);
                }

                this.page++;
                logger.info('Successfully loaded messages page:', this.page - 1);
            }
        } catch (error) {
            logger.error('Error loading messages:', error);
        } finally {
            this.isLoadingMessages = false;
        }
    }

    renderMessages(messages, prepend = false) {
        if (!messages || messages.length === 0 || !this.chatMessages) return;
        const scrollPos = this.chatMessages.scrollHeight - this.chatMessages.scrollTop;
        const fragment = document.createDocumentFragment();

        messages.forEach(msg => {
            const messageElement = document.createElement('div');
            const isSent = msg.senderId === this.currentUserId;

            messageElement.className = `message ${isSent ? 'outgoing' : 'incoming'}`;
            messageElement.dataset.messageId = msg.id;

            const timestamp = msg.timestamp || new Date().toISOString();
            const date = new Date(timestamp);
            const formattedDate = date.toLocaleTimeString([],
                { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
            const sender = msg.senderName || (isSent ? this.currentNickname : this.getChatUserName());

            const readStatus = isSent ? this.getReadStatusHtml(msg.is_read) : '';

            messageElement.innerHTML = `
                <div class="message-bubble">
                    <div class="message-content">${msg.content}</div>
                    <div class="message-meta">
                       ${sender} • ${formattedDate}
                        ${readStatus}
                    </div>
                </div>
            `;

            fragment.appendChild(messageElement);
        });

        if (prepend) {
            this.chatMessages.prepend(fragment);
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight - scrollPos;
        } else {
            this.chatMessages.appendChild(fragment);
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
        }
    }

    getReadStatusHtml(isRead) {
        return `
            <span class="message-status ${isRead ? 'read' : ''}">
                <i class="fas fa-check"></i><i class="fas fa-check second-check"></i>
            </span>
        `;
    }

    getChatUserName() {
        return this.chatUserName ? this.chatUserName.textContent : 'User';
    }

    handleMessageSubmit(e) {
        e.preventDefault();

        if (!this.chatInput) return;

        const content = this.chatInput.value.trim();

        if (content && this.currentChatUserId) {
            const optimisticMsg = {
                id: 'temp-' + Date.now(),
                senderId: this.currentUserId,
                senderName: this.currentNickname,
                receiverId: this.currentChatUserId,
                content: content,
                timestamp: new Date().toISOString()
            };

            if (!this.messages[this.currentChatUserId]) {
                this.messages[this.currentChatUserId] = [];
            }
            this.messages[this.currentChatUserId].push(optimisticMsg);

            this.renderMessages([optimisticMsg]);

            this.sendPrivateMessage(this.currentChatUserId, content);
            this.chatInput.value = '';
        }
    }

    sendPrivateMessage(receiverId, content) {
        const messageSent = webSocketManager.sendMessage('privateMessage', {
            receiverId: receiverId,
            content: content
        });

        if (!messageSent) {
            apiRequests.sendMessage(receiverId, content)
                .then(response => {
                    if (response.success) {
                        const tempMsg = document.querySelector(`[data-message-id="temp-${Date.now()}"]`);
                        if (tempMsg && response.message && response.message.id) {
                            tempMsg.dataset.messageId = response.message.id;
                        }
                    }
                })
                .catch(error => {
                    logger.error('Failed to send message via API:', error);
                });
        }
    }

    handleIncomingMessage(message) {
        const isCurrentChat = this.currentChatUserId === message.senderId ||
            this.currentChatUserId === message.receiverId;

        const userId = message.senderId === this.currentUserId ?
            message.receiverId : message.senderId;

        if (!this.messages[userId]) {
            this.messages[userId] = [];
        }
        this.messages[userId].push(message);

        if (isCurrentChat) {
            this.renderMessages([message]);
            if (message.senderId !== this.currentUserId) {
                this.markMessagesAsRead(message.senderId);
            }
        } else if (message.senderId !== this.currentUserId) {
            if (!this.unreadMessages[message.senderId]) {
                this.unreadMessages[message.senderId] = 0;
            }
            this.unreadMessages[message.senderId]++;

            this.updateUnreadCount();
            this.renderUsers();
        }
    }

    async markMessagesAsRead(userId) {
        try {
            this.clearUnread(userId);

            webSocketManager.sendMessage('readReceipt', {
                readerId: this.currentUserId,
                senderId: userId
            });
            this.markAsRead(userId);
        } catch (error) {
            logger.error('Error marking messages as read:', error);
        }
    }

    clearUnread(userId) {
        if (this.unreadMessages[userId]) {
            this.unreadMessages[userId] = 0;
            this.updateUnreadCount();
            this.renderUsers(); // Re-render users to remove unread indicator
        }
    }

    handleTyping() {
        if (!this.currentChatUserId) return;
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }

        webSocketManager.sendMessage('typingIndicator', {
            receiverId: this.currentChatUserId,
            isTyping: true
        });

        this.typingTimeout = setTimeout(() => {
            webSocketManager.sendMessage('typingIndicator', {
                receiverId: this.currentChatUserId,
                isTyping: false
            });
        }, 2000);
    }

    showTypingIndicator(data) {
        if (!this.typingIndicator) {
            logger.error('No typing indicator element found');
            return;
        }

        if (data.senderId === this.currentChatUserId) {
            if (data.isTyping) {
                this.typingIndicator.classList.remove('hidden');
                const userName = this.chatUserName ? this.chatUserName.textContent : 'User';
                this.typingIndicator.innerHTML = `
                    ${userName} is typing<span></span><span></span><span></span>
                `;
            } else {
                this.typingIndicator.classList.add('hidden');
                this.typingIndicator.innerHTML = '';
            }
        } else {
            logger.info('Ignoring typing indicator - not from current chat user', {
                senderId: data.senderId,
                currentChatUserId: this.currentChatUserId
            });
        }
    }

    updateUserStatus(userId, isOnline) {
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].online = isOnline;
        }

        if (this.currentChatUserId === userId && this.chatUserStatus) {
            this.chatUserStatus.textContent = isOnline ? 'Online' : 'Offline';
            this.chatUserStatus.className = `user-status ${isOnline ? 'online' : 'offline'}`;
        }

        const userItem = this.usersList ? this.usersList.querySelector(`[data-user-id="${userId}"]`) : null;
        if (userItem) {
            const statusIndicator = userItem.querySelector('.user-status-indicator');
            if (statusIndicator) {
                statusIndicator.className = `user-status-indicator ${isOnline ? 'online' : 'offline'}`;
            }
        }
    }

    updateUnreadCount() {
        if (!this.unreadCountElement) return;
        const totalUnread = Object.values(this.unreadMessages).reduce((sum, count) => sum + count, 0);

        if (totalUnread > 0) {
            this.unreadCountElement.textContent = totalUnread > 99 ? '99+' : totalUnread;
            this.unreadCountElement.classList.remove('hidden');
        } else {
            this.unreadCountElement.classList.add('hidden');
        }
    }

    markMessageAsRead(data) {
        const messageElements = document.querySelectorAll(`.message[data-message-id]`);
        messageElements.forEach(element => {
            const statusElement = element.querySelector('.message-status');
            if (statusElement) {
                statusElement.classList.add('read');
            }
        });
    }

    // Mark a message as read
    markAsRead(data) {
        const messageElement = document.querySelector(`[data-message-id='${data.messageId}']`);
        if (messageElement) {
            messageElement.classList.add('read');
        }
    }

    getLastMessageTime(userId) {
        // First prioritize server-provided timestamps
        if (this.messages[userId] && this.messages[userId].lastServerTime) {
            return this.messages[userId].lastServerTime;
        }

        // Then check for locally stored messages
        if (this.messages[userId] && this.messages[userId].length > 0) {
            const lastMessage = this.messages[userId][this.messages[userId].length - 1];
            return new Date(lastMessage.timestamp).getTime();
        }

        return null;
    }
    handleScroll() {
        if (this.chatMessages && this.chatMessages.scrollTop < 50 &&
            !this.isLoadingMessages && this.hasMoreMessages) {
            this.loadMessages();
        }
    }

    toggleChatContainer() {
        if (!this.chatContainer) return;

        // If we're in a chat conversation, go back to the user list first
        if (this.chatContainer.classList.contains('chat-active')) {
            this.goBackToUserList();
            return;
        }

        const isCurrentlyExpanded = this.chatContainer.classList.contains('chat-expanded');
        if (isCurrentlyExpanded) { // If currently expanded, collapse it
            this.chatContainer.classList.remove('chat-expanded');

            if (this.chatToggle) {
                const icon = this.chatToggle.querySelector('i');
                if (icon) {
                    icon.className = 'fas fa-comments'; // Update button icon
                }
            }
        } else { // expand it
            this.chatContainer.classList.add('chat-expanded');
            this.chatContainer.classList.remove('chat-hidden');
            this.chatContainer.style.display = ''; // Remove any display:none

            if (this.chatToggle) {
                const icon = this.chatToggle.querySelector('i');
                if (icon) {
                    icon.className = 'fas fa-times'; // Update button icon
                }
            }
        }

        // Store the state in localStorage for persistence across page loads
        localStorage.setItem('chat-expanded', (!isCurrentlyExpanded).toString());
        logger.info(`Chat container ${!isCurrentlyExpanded ? 'expanded' : 'collapsed'}`);
    }

    render() {
        console.log('[Chat] render() called');
        const chatContainer = document.getElementById('chat-container');
        if (!chatContainer) {
            console.error('[Chat] #chat-container not found in DOM');
            return;
        }
        console.log('[Chat] rendering into', chatContainer);

        // Check if we should restore expanded state from previous session
        const wasExpanded = localStorage.getItem('chat-expanded') === 'true';
        if (wasExpanded) {
            chatContainer.classList.add('chat-expanded');
        }

        chatContainer.innerHTML = `
            <div class="chat-sidebar">
                <h3>Messages</h3>
                <div class="online-users-header">
                    <h4>Online Users</h4>
                </div>
                <div class="user-search">
                    <input type="text" id="user-search" placeholder="Search users...">
                </div>
                <ul id="users-list" class="users-list"></ul>
            </div>
            <div class="chat-main" id="chat-main">
                <div class="chat-header">
                    <button class="back-button" id="back-button">
                        <i class="fas fa-arrow-left"></i>
                    </button>
                    <div class="chat-header-info">
                        <h4 id="chat-user-name">User Name</h4>
                        <span id="chat-user-status" class="user-status">online</span>
                    </div>
                </div>
                <div class="chat-messages" id="chat-messages"></div>
                <div class="typing-indicator hidden" id="typing-indicator"></div>
                <div class="chat-form-container">
                    <form id="chat-form">
                        <input id="chat-input" type="text" placeholder="Type a message..." required autocomplete="off" />
                        <button class="send-btn">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </form>
                </div>
            </div>

            <!-- Chat toggle button for mobile/responsive view -->
            <button id="chat-toggle" class="chat-toggle">
                <i class="fas fa-${wasExpanded ? 'times' : 'comments'}"></i>
                <span class="unread-count hidden" id="unread-count">0</span>
            </button>
        `;
        // Initialize all DOM elements
        this.initElements();

        // Initialize the chat functionality
        this.initializeChat().then(success => {
            if (success) {
                logger.info('[Chat] Successfully initialized after render');
            } else {
                logger.error('[Chat] Failed to initialize after render');
            }
        });
    }

    static throttle(callback, delay) {
        let lastCall = 0;
        return function (...args) {
            const now = new Date().getTime();
            if (now - lastCall < delay) {
                return;
            }
            lastCall = now;
            return callback(...args);
        };
    }

    static debounce(callback, delay) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => callback(...args), delay);
        };
    }
}

// Create global reference for event handlers
const chat = new Chat();
window.addEventListener('DOMContentLoaded', () => chat.render());
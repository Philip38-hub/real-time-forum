/**
 * Private messaging functionality
 */

const Chat = {
    currentUserId: null,
    currentUsername: null,
    currentChatUserId: null,
    typingTimeout: null,
    users: [],
    messages: {}, // Store messages by user ID
    unreadMessages: {}, // Track unread messages count
    page: 1,
    isLoadingMessages: false,
    hasMoreMessages: true,

    async initializeChat() {
        try {
            // Fetch user profile data from the backend
            const response = await fetch('/api/current-user', { credentials: 'include' }); // Include cookies
            if (!response.ok) {
                throw new Error('Failed to fetch user profile');
            }

            const userInfo = await response.json();

            // Assign globally
            this.currentUserId = userInfo.userId; 
            this.currentUsername = userInfo.username;

            console.log('User profile loaded:', userInfo);

            // Initialize chat functionality
            this.init();
        } catch (error) {
            console.error('Error initializing chat:', error);
        }
    },
    
    init() {
        this.initElements();
        this.fetchUsers();
        this.attachEventListeners();
        this.registerWebSocketHandlers();
        this.updateUnreadCount();
    },

    //    Initialize DOM elements
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
    },
    
    // Register WebSocket message handlers for chat-related messages
    registerWebSocketHandlers() {
        // Handle private messages
        webSocketManager.registerHandler('privateMessage', (content) => {
            if (content.receiverId === this.currentUserId || content.senderId === this.currentUserId) {
                this.handleIncomingMessage(content);
            }
        });
        
        // Handle typing indicators
        webSocketManager.registerHandler('typingIndicator', (content) => {
            if (content.receiverId === this.currentUserId) {
                this.showTypingIndicator(content);
            }
        });
        
        // Handle read receipts
        webSocketManager.registerHandler('readReceipt', (content) => {
            if (content.senderId === this.currentUserId) {
                this.markMessageAsRead(content);
            }
        });
        
        // Handle user status updates
        webSocketManager.registerHandler('userStatus', (content) => {
            this.updateUserStatus(content.userId, content.online);
        });

        // handler for messageSent confirmation
        webSocketManager.registerHandler('messageSent', (content) => {
            logger.info('Message delivered:', content.messageId);
        });
    },
    
    attachEventListeners() {
        // Chat toggle button
        if (this.chatToggle) {
            this.chatToggle.addEventListener('click', this.toggleChatContainer.bind(this));
        }
        
        // Minimize chat button
        if (this.minimizeBtn) {
            this.minimizeBtn.addEventListener('click', this.minimizeChat.bind(this));
        }
        
        // Close chat button
        if (this.closeBtn) {
            this.closeBtn.addEventListener('click', this.closeChat.bind(this));
        }
        
        // Chat form submission
        if (this.chatForm) {
            this.chatForm.addEventListener('submit', this.handleMessageSubmit.bind(this));
        }
        
        // Typing indicator
        if (this.chatInput) {
            this.chatInput.addEventListener('input', this.handleTyping.bind(this));
        }
        
        // Load more messages when scrolling up
        if (this.chatMessages) {
            this.chatMessages.addEventListener('scroll', throttle(() => this.handleScroll(), 500));
        }
        
        // Filter users
        if (this.userSearch) {
            this.userSearch.addEventListener('input', debounce((e) => this.filterUsers(e.target.value), 300));
        }
    },
    
    // toggleChatContainer()
    // minimizeChat()
    // closeChat()
    
    async fetchUsers() {
        try {
            const response = await api.fetchUsers();
            if (response.success) {
                this.users = response.users;
                this.renderUsers();
            } else {
                logger.error('Failed to fetch users:', response.message);
            }
        } catch (error) {
            logger.error('Error fetching users:', error);
        }
    },
    
    renderUsers() {
        if (!this.usersList) return;
        
        this.usersList.innerHTML = ''; // Clear existing users
    
         // Sort users: first by last message time, then alphabetically
         const sortedUsers = [...this.users].sort((a, b) => {
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
            
            // If neither has messages, sort alphabetically
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
    },
    
   // Filter users by search term
   filterUsers(searchTerm) {
        const items = this.usersList.querySelectorAll('li');
        const lowerSearchTerm = searchTerm.toLowerCase();
        
        items.forEach(item => {
            const username = item.querySelector('.user-name').textContent.toLowerCase();
            if (username.includes(lowerSearchTerm)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    },

    async openChat(user) {
        this.currentChatUserId = user.id;

        // Update chat header
        if (this.chatUserName) this.chatUserName.textContent = user.nickname;
        if (this.chatUserStatus) {
            this.chatUserStatus.textContent = user.online ? 'Online' : 'Offline';
            this.chatUserStatus.className = `user-status ${user.online ? 'online' : 'offline'}`;
        }

        // Show chat main section
        if (this.chatMain) this.chatMain.classList.remove('hidden');

        // Clear messages area
        if (this.chatMessages) this.chatMessages.innerHTML = '';
        
        // Reset pagination
        this.page = 1;
        this.hasMoreMessages = true;
        await this.loadMessages(); // Load messages
        this.markMessagesAsRead(user.id); // Mark messages as read
        if (this.chatInput) this.chatInput.focus(); // Focus on input
    },

    async loadMessages() {
        if (!this.currentChatUserId || this.isLoadingMessages || !this.hasMoreMessages) return;
        
        try {
            this.isLoadingMessages = true;
            
            // Show loading indicator
            const loadingEl = document.createElement('div');
            loadingEl.className = 'loading-messages';
            loadingEl.textContent = 'Loading messages...';
            this.chatMessages.prepend(loadingEl);
            
            const response = await api.fetchMessages(this.currentChatUserId, this.page);
            
            // Remove loading indicator
            loadingEl.remove();
            
            if (response.success) {
                const messages = response.messages || [];
                this.hasMoreMessages = messages.length === 10; // Check if we have more messages
                
                // Store messages
                if (!this.messages[this.currentChatUserId]) {
                    this.messages[this.currentChatUserId] = [];
                }
                
                // Add messages to the beginning of the array
                this.messages[this.currentChatUserId] = [
                    ...messages,
                    ...this.messages[this.currentChatUserId]
                ];
                this.renderMessages(messages, true); // Render messages
                this.page++; // Increment page for next load
            }
        } catch (error) {
            logger.error('Error loading messages:', error);
        } finally {
            this.isLoadingMessages = false;
        }
    },
    
    renderMessages(messages, prepend = false) {
        if (!messages || messages.length === 0 || !this.chatMessages) return;
        const scrollPos = this.chatMessages.scrollHeight - this.chatMessages.scrollTop;
        const fragment = document.createDocumentFragment();
        
        messages.forEach(msg => {
            const messageElement = document.createElement('div');
            const isSent = msg.senderId === this.currentUserId;
            
            messageElement.className = `message ${isSent ? 'sent' : 'received'}`;
            messageElement.dataset.messageId = msg.id;
            
            const timestamp = msg.timestamp || new Date().toISOString();
            const date = new Date(timestamp);
            const formattedDate = date.toLocaleString();
            const sender = msg.senderName || (isSent ? this.currentUsername : this.getChatUserName());
            
            messageElement.innerHTML = `
                <div class="message-content">${msg.content}</div>
                <div class="message-info">
                    ${sender} • ${formattedDate}
                </div>
            `;
            
            fragment.appendChild(messageElement);
        });
        
        if (prepend) {
            // Insert at the beginning
            this.chatMessages.prepend(fragment);
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight - scrollPos;
        } else {
            // Append at the end
            this.chatMessages.appendChild(fragment);
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
        }
    },
    
    getChatUserName() {
        return this.chatUserName ? this.chatUserName.textContent : 'User';
    },
    
    handleMessageSubmit(e) {
        e.preventDefault();
    
        if (!this.chatInput) return;
        
        const content = this.chatInput.value.trim();
    
        if (content && this.currentChatUserId) {
            const optimisticMsg = {
                id: 'temp-' + Date.now(),
                senderId: this.currentUserId,
                senderName: this.currentUsername,
                receiverId: this.currentChatUserId,
                content: content,
                timestamp: new Date().toISOString()
            };
            
            // Add to local messages
            if (!this.messages[this.currentChatUserId]) {
                this.messages[this.currentChatUserId] = [];
            }
            this.messages[this.currentChatUserId].push(optimisticMsg);
            
            this.renderMessages([optimisticMsg]);
            
            // Send message via WebSocket
            this.sendPrivateMessage(this.currentChatUserId, content); 
            this.chatInput.value = ''; // Clear input
        }
    },
    
    sendPrivateMessage(receiverId, content) {
        const messageSent = webSocketManager.sendMessage('privateMessage', {
            receiverId: receiverId,
            content: content
        });
        
        // If WebSocket failed, send via API as fallback
        if (!messageSent) {
            api.sendMessage(receiverId, content)
                .then(response => {
                    if (response.success) {
                        // Update temp message with real ID if available
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
    },
    
    handleIncomingMessage(message) {
        const isCurrentChat = this.currentChatUserId === message.senderId || 
                            this.currentChatUserId === message.receiverId;
        
        const userId = message.senderId === this.currentUserId ? 
                      message.receiverId : message.senderId;
        
        if (!this.messages[userId]) {
            this.messages[userId] = [];
        }
        this.messages[userId].push(message);
        
        // If in current chat, render message
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
            this.renderUsers(); // Update user list to show unread indicator
        }
    },

    async markMessagesAsRead(userId) {
        try {
            this.clearUnread(userId);
            
            webSocketManager.sendMessage('readReceipt', {
                readerId: this.currentUserId,
                senderId: userId
            });
            await UI.markMessageAsRead(userId); // Mark messages as read in UI
        } catch (error) {
            logger.error('Error marking messages as read:', error);
        }
    },
    
    clearUnread(userId) {
        if (this.unreadMessages[userId]) {
            this.unreadMessages[userId] = 0;
            this.updateUnreadCount();
        }
    },

    handleTyping() {
        if (!this.currentChatUserId) return;
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout); // Clear existing timeout
        }
        
        // Send typing indicator
        webSocketManager.sendMessage('typingIndicator', {
            senderId: this.currentUserId,
            receiverId: this.currentChatUserId,
            typing: true
        });
        
        // Set timeout to stop typing indicator
        this.typingTimeout = setTimeout(() => {
            webSocketManager.sendMessage('typingIndicator', {
                senderId: this.currentUserId,
                receiverId: this.currentChatUserId,
                typing: false
            });
        }, 2000);
    },
    
    showTypingIndicator(data) {
        if (!this.typingIndicator || data.senderId !== this.currentChatUserId) return;
        
        if (data.typing) {
            this.typingIndicator.classList.remove('hidden');
        } else {
            this.typingIndicator.classList.add('hidden');
        }
    },
    
    updateUserStatus(userId, isOnline) {
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].online = isOnline;
        }
        
        // Update in current chat if applicable
        if (this.currentChatUserId === userId && this.chatUserStatus) {
            this.chatUserStatus.textContent = isOnline ? 'Online' : 'Offline';
            this.chatUserStatus.className = `user-status ${isOnline ? 'online' : 'offline'}`;
        }
        
        // Update in user list
        const userItem = this.usersList ? this.usersList.querySelector(`[data-user-id="${userId}"]`) : null;
        if (userItem) {
            const statusIndicator = userItem.querySelector('.user-status-indicator');
            if (statusIndicator) {
                statusIndicator.className = `user-status-indicator ${isOnline ? 'online' : 'offline'}`;
            }
        }
    },
    
    updateUnreadCount() {
        if (!this.unreadCountElement) return;
        const totalUnread = Object.values(this.unreadMessages).reduce((sum, count) => sum + count, 0);
        
        if (totalUnread > 0) {
            this.unreadCountElement.textContent = totalUnread > 99 ? '99+' : totalUnread;
            this.unreadCountElement.classList.remove('hidden');
        } else {
            this.unreadCountElement.classList.add('hidden');
        }
    },
    
    markMessageAsRead(data) {
        // Update UI to show message has been read
        const userElement = document.querySelector(`.user[data-user-id="${data.readerId}"]`);
        if (!userElement) return;
        
        const unreadElement = userElement.querySelector('.unread-count');
        if (unreadElement) {
            unreadElement.remove();
        }
    },
     // Get last message time for a user (for sorting)
     getLastMessageTime(userId) {
        if (!this.messages[userId] || this.messages[userId].length === 0) {
            return null;
        }
        
        const lastMessage = this.messages[userId][this.messages[userId].length - 1];
        return new Date(lastMessage.timestamp).getTime();
    },

     // Handle scroll in messages container
     handleScroll() {
        // If scrolled to top, load more messages
        if (this.chatMessages && this.chatMessages.scrollTop === 0 && 
            !this.isLoadingMessages && this.hasMoreMessages) {
            this.loadMessages();
        }
    },
};

// Utility function to throttle scroll events
function throttle(callback, delay) {
    let lastCall = 0;
    return function(...args) {
        const now = new Date().getTime();
        if (now - lastCall < delay) {
            return;
        }
        lastCall = now;
        return callback(...args);
    };
}

// Utility function to debounce search input
function debounce(callback, delay) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => callback(...args), delay);
    };
}

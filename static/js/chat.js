/**
 * Private messaging functionality
 */

const Chat = {
    currentChatUser: null,
    users: [],
    messages: {},
    unreadMessages: {},
    isMinimized: false,
    page: 1,
    isLoadingMessages: false,
    hasMoreMessages: true,

    /**
     * Initialize chat functionality
     */
    init() {
        this.initElements();
        this.attachEventListeners();
        this.updateUnreadCount();
    },

    /**
     * Initialize DOM elements
     */
    initElements() {
        this.chatToggle = document.getElementById('chat-toggle');
        this.chatContainer = document.getElementById('chat-container');
        this.minimizeBtn = document.getElementById('minimize-chat');
        this.closeBtn = document.getElementById('close-chat');
        this.chatMain = document.getElementById('chat-main');
        this.usersList = document.getElementById('users-list');
        this.chatMessages = document.getElementById('chat-messages');
        this.chatForm = document.getElementById('chat-form');
        this.chatInput = document.getElementById('chat-input');
        this.chatUserName = document.getElementById('chat-user-name');
        this.chatUserStatus = document.getElementById('chat-user-status');
        this.userSearch = document.getElementById('user-search');
        this.unreadCountElement = document.getElementById('unread-count');
    },

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        // Toggle chat sidebar
        this.chatToggle.addEventListener('click', () => this.toggleChat());
        
        // Minimize chat
        this.minimizeBtn.addEventListener('click', () => this.minimizeChat());
        
        // Close current chat
        this.closeBtn.addEventListener('click', () => this.closeCurrentChat());
        
        // Send message
        this.chatForm.addEventListener('submit', (e) => this.handleSendMessage(e));
        
        // Load more messages when scrolling up
        this.chatMessages.addEventListener('scroll', throttle(() => this.handleScroll(), 500));
        
        // Filter users
        this.userSearch.addEventListener('input', debounce((e) => this.filterUsers(e.target.value), 300));
    },

    /**
     * Toggle chat sidebar visibility
     */
    toggleChat() {
        toggleElement(this.chatContainer);
        
        if (!this.chatContainer.classList.contains('hidden')) {
            this.isMinimized = false;
            this.chatContainer.classList.remove('minimized');
            this.loadUsers(); // Reload users when opening chat
        }
    },

    /**
     * Minimize chat window
     */
    minimizeChat() {
        this.isMinimized = !this.isMinimized;
        this.chatContainer.classList.toggle('minimized');
    },

    /**
     * Close current chat conversation
     */
    closeCurrentChat() {
        hideElement(this.chatMain);
        this.currentChatUser = null;
    },

    /**
     * Load all users
     */
    async loadUsers() {
        try {
            const response = await api.fetchUsers();
            
            if (response && response.success) {
                this.users = response.users;
                this.renderUsers();
            }
        } catch (error) {
            logger.error('Error loading users:', error);
        }
    },

    /**
     * Render users list
     */
    renderUsers() {
        this.usersList.innerHTML = '';
        
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
            return a.nickname.localeCompare(b.nickname);   // 2 nickname
        });
        
        sortedUsers.forEach(user => {
            const listItem = document.createElement('li');
            listItem.setAttribute('data-user-id', user.id);
            listItem.addEventListener('click', () => this.openChat(user));
            
            const hasUnread = this.unreadMessages[user.id] && this.unreadMessages[user.id] > 0;
            
            listItem.innerHTML = `
                <span class="user-status-indicator ${user.online ? 'online' : 'offline'}"></span>
                <span class="user-name">${user.nickname}</span>
                ${hasUnread ? '<span class="unread-indicator"></span>' : ''}
            `;
            
            this.usersList.appendChild(listItem);
        });
    },

    /**
     * Filter users by search term
     */
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

    /**
     * Open chat with specific user
     */
    async openChat(user) {
        // Set current chat user
        this.currentChatUser = user;
        
        // Update UI
        this.chatUserName.textContent = user.nickname;
        this.chatUserStatus.textContent = user.online ? 'online' : 'offline';
        this.chatUserStatus.className = `user-status ${user.online ? 'online' : 'offline'}`;
        
        // Show chat main
        showElement(this.chatMain);
        
        // Clear messages area
        this.chatMessages.innerHTML = '';
        
        // Reset pagination
        this.page = 1;
        this.hasMoreMessages = true;
        
        // Load messages
        await this.loadMessages();
        
        // Clear unread for this user
        this.clearUnread(user.id);
        
        // Focus input
        this.chatInput.focus();
    },

    /**
     * Load messages for current chat
     */
    async loadMessages() {
        if (!this.currentChatUser || this.isLoadingMessages || !this.hasMoreMessages) return;
        
        try {
            this.isLoadingMessages = true;
            
            // Show loading indicator
            const loadingEl = document.createElement('div');
            loadingEl.className = 'loading-messages';
            loadingEl.textContent = 'Loading messages...';
            this.chatMessages.prepend(loadingEl);
            
            const response = await api.fetchMessages(this.currentChatUser.id, this.page);
            
            // Remove loading indicator
            loadingEl.remove();
            
            if (response && response.success) {
                // Check if we have more messages
                this.hasMoreMessages = response.messages.length === 10;
                
                // Store messages
                if (!this.messages[this.currentChatUser.id]) {
                    this.messages[this.currentChatUser.id] = [];
                }
                
                // Add messages to the beginning of the array
                this.messages[this.currentChatUser.id] = [
                    ...response.messages,
                    ...this.messages[this.currentChatUser.id]
                ];
                
                // Render messages
                this.renderMessages(response.messages, true);
                
                // Increment page for next load
                this.page++;
            }
        } catch (error) {
            logger.error('Error loading messages:', error);
        } finally {
            this.isLoadingMessages = false;
        }
    },

    /**
     * Render messages in chat
     * @param {Array} messages - Messages to render
     * @param {Boolean} prepend - Whether to prepend or append messages
     */
    renderMessages(messages, prepend = false) {
        if (!messages || messages.length === 0) return;
        
        // Get current scroll position
        const scrollPos = this.chatMessages.scrollHeight - this.chatMessages.scrollTop;
        
        // Create document fragment for better performance
        const fragment = document.createDocumentFragment();
        
        messages.forEach(msg => {
            const messageEl = document.createElement('div');
            messageEl.className = `message ${msg.senderId === localStorage.getItem('userId') ? 'outgoing' : 'incoming'}`;
            messageEl.setAttribute('data-message-id', msg.id);
            
            const date = new Date(msg.timestamp);
            const formattedDate = date.toLocaleString();
            
            messageEl.innerHTML = `
                <div class="message-content">${msg.content}</div>
                <div class="message-info">
                    ${msg.sender} • ${formattedDate}
                </div>
            `;
            
            fragment.appendChild(messageEl);
        });
        
        if (prepend) {
            // Insert at the beginning
            this.chatMessages.prepend(fragment);
            
            // Maintain scroll position when loading older messages
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight - scrollPos;
        } else {
            // Append at the end
            this.chatMessages.appendChild(fragment);
            
            // Scroll to bottom for new messages
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
        }
    },

    /**
     * Handle sending a message
     */
    async handleSendMessage(event) {
        event.preventDefault();
        
        if (!this.currentChatUser) return;
        
        const content = this.chatInput.value.trim();
        if (!content) return;
        
        try {
            const userId = localStorage.getItem('userId');
            const username = localStorage.getItem('username');
            
            // Optimistically add message to UI
            const optimisticMsg = {
                id: 'temp-' + Date.now(),
                senderId: userId,
                sender: username,
                receiverId: this.currentChatUser.id,
                content: content,
                timestamp: new Date().toISOString()
            };
            
            // Add to local messages
            if (!this.messages[this.currentChatUser.id]) {
                this.messages[this.currentChatUser.id] = [];
            }
            this.messages[this.currentChatUser.id].push(optimisticMsg);
            
            // Render message
            this.renderMessages([optimisticMsg]);
            
            // Clear input
            this.chatInput.value = '';
            
            // Send message to server
            const response = await api.sendMessage(this.currentChatUser.id, content);
            
            if (!response || !response.success) {
                throw new Error(response?.message || 'Failed to send message');
            }
            
            // Update optimistic message with real ID if needed
            if (response.messageId) {
                const tempMsg = document.querySelector(`[data-message-id="temp-${Date.now()}"]`);
                if (tempMsg) {
                    tempMsg.setAttribute('data-message-id', response.messageId);
                }
            }
        } catch (error) {
            logger.error('Error sending message:', error);
            alert('Failed to send message. Please try again.');
        }
    },

    /**
     * Handle scroll in messages container
     */
    handleScroll() {
        // If scrolled to top, load more messages
        if (this.chatMessages.scrollTop === 0 && !this.isLoadingMessages && this.hasMoreMessages) {
            this.loadMessages();
        }
    },

    /**
     * Handle incoming message from WebSocket
     */
    handleIncomingMessage(message) {
        // Check if message is for current chat
        const isCurrentChat = this.currentChatUser && 
            (message.senderId === this.currentChatUser.id || message.receiverId === this.currentChatUser.id);
        
        // Store message
        const userId = message.senderId;
        if (!this.messages[userId]) {
            this.messages[userId] = [];
        }
        this.messages[userId].push(message);
        
        // If in current chat, render message
        if (isCurrentChat) {
            this.renderMessages([message]);
        } else {
            // Increment unread count
            if (!this.unreadMessages[userId]) {
                this.unreadMessages[userId] = 0;
            }
            this.unreadMessages[userId]++;
            
            // Update UI
            this.updateUnreadCount();
            this.renderUsers(); // Update user list to show unread indicator
        }
    },

    /**
     * Clear unread messages for a user
     */
    clearUnread(userId) {
        if (this.unreadMessages[userId]) {
            this.unreadMessages[userId] = 0;
            this.updateUnreadCount();
            
            // Update user list
            const userItem = this.usersList.querySelector(`[data-user-id="${userId}"]`);
            if (userItem) {
                const indicator = userItem.querySelector('.unread-indicator');
                if (indicator) {
                    indicator.remove();
                }
            }
        }
    },

    /**
     * Update unread count badge
     */
    updateUnreadCount() {
        const totalUnread = Object.values(this.unreadMessages).reduce((sum, count) => sum + count, 0);
        
        if (totalUnread > 0) {
            this.unreadCountElement.textContent = totalUnread > 99 ? '99+' : totalUnread;
            showElement(this.unreadCountElement);
        } else {
            hideElement(this.unreadCountElement);
        }
    },

    /**
     * Get last message time for a user
     */
    getLastMessageTime(userId) {
        if (!this.messages[userId] || this.messages[userId].length === 0) {
            return null;
        }
        
        const lastMessage = this.messages[userId][this.messages[userId].length - 1];
        return new Date(lastMessage.timestamp).getTime();
    },

    /**
     * Update user online status
     */
    updateUserStatus(userId, isOnline) {
        // Update in users array
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].online = isOnline;
        }
        
        // Update in current chat if applicable
        if (this.currentChatUser && this.currentChatUser.id === userId) {
            this.chatUserStatus.textContent = isOnline ? 'online' : 'offline';
            this.chatUserStatus.className = `user-status ${isOnline ? 'online' : 'offline'}`;
        }
        
        // Update in user list
        const userItem = this.usersList.querySelector(`[data-user-id="${userId}"]`);
        if (userItem) {
            const statusIndicator = userItem.querySelector('.user-status-indicator');
            if (statusIndicator) {
                statusIndicator.className = `user-status-indicator ${isOnline ? 'online' : 'offline'}`;
            }
        }
    }
};

// // Chat module for handling private messaging
// const chatModule = {
//     currentChatUserId: null,
//     typingTimeout: null,
    
//     init() {
//         this.fetchUsers();
//         this.attachEventListeners();
//         this.registerWebSocketHandlers();
//     },
    
//     // Register WebSocket message handlers for chat-related messages
//     registerWebSocketHandlers() {
//         // Handle private messages
//         webSocketManager.registerHandler('private_message', (content) => {
//             if (content.receiver_id === currentUserId || content.sender_id === currentUserId) {
//                 this.addNewMessage(content);
//             }
//         });
        
//         // Handle typing indicators
//         webSocketManager.registerHandler('typing_indicator', (content) => {
//             if (content.receiver_id === currentUserId) {
//                 this.showTypingIndicator(content);
//             }
//         });
        
//         // Handle read receipts
//         webSocketManager.registerHandler('read_receipt', (content) => {
//             if (content.sender_id === currentUserId) {
//                 this.markMessageAsRead(content);
//             }
//         });
        
//         // Handle user status updates
//         webSocketManager.registerHandler('user_status', (content) => {
//             this.updateUserStatus(content);
//         });
//     },
    
//     attachEventListeners() {
//         // Chat toggle button
//         const chatToggleBtn = document.getElementById('chat-toggle');
//         if (chatToggleBtn) {
//             chatToggleBtn.addEventListener('click', this.toggleChatContainer.bind(this));
//         }
        
//         // Minimize chat button
//         const minimizeChatBtn = document.getElementById('minimize-chat');
//         if (minimizeChatBtn) {
//             minimizeChatBtn.addEventListener('click', this.minimizeChat.bind(this));
//         }
        
//         // Close chat button
//         const closeChatBtn = document.getElementById('close-chat');
//         if (closeChatBtn) {
//             closeChatBtn.addEventListener('click', this.closeChat.bind(this));
//         }
        
//         // Chat form submission
//         const chatForm = document.getElementById('chat-form');
//         if (chatForm) {
//             chatForm.addEventListener('submit', this.handleMessageSubmit.bind(this));
//         }
        
//         // Typing indicator
//         const chatInput = document.getElementById('chat-input');
//         if (chatInput) {
//             chatInput.addEventListener('input', this.handleTyping.bind(this));
//         }
//     },
    
//     toggleChatContainer() {
//         const chatContainer = document.getElementById('chat-container');
//         if (chatContainer) {
//             chatContainer.classList.toggle('hidden');
//         }
//     },
    
//     minimizeChat() {
//         const chatMain = document.getElementById('chat-main');
//         if (chatMain) {
//             chatMain.classList.toggle('hidden');
//         }
//     },
    
//     closeChat() {
//         const chatMain = document.getElementById('chat-main');
//         if (chatMain) {
//             chatMain.classList.add('hidden');
//         }
//         this.currentChatUserId = null;
//     },
    
//     async fetchUsers() {
//         try {
//             const response = await api.fetchUsers();
//             if (response.success) {
//                 this.renderUsers(response.users);
//             } else {
//                 logger.error('Failed to fetch users:', response.message);
//             }
//         } catch (error) {
//             logger.error('Error fetching users:', error);
//         }
//     },
    
//     renderUsers(users) {
//         const usersList = document.getElementById('users-list');
//         if (!usersList) return;
        
//         usersList.innerHTML = ''; // Clear existing users
    
//         users.forEach(user => {
//             const userElement = document.createElement('li');
//             userElement.className = 'user';
//             userElement.dataset.userId = user.id;
//             userElement.innerHTML = `
//                 <span class="user-name">${user.nickname}</span>
//                 <span class="user-status ${user.online ? 'online' : 'offline'}">
//                     ${user.online ? 'Online' : 'Offline'}
//                 </span>
//                 ${user.unread > 0 ? `<span class="unread-count">${user.unread}</span>` : ''}
//             `;
    
//             userElement.addEventListener('click', () => this.openChat(user.id, user.nickname));
//             usersList.appendChild(userElement);
//         });
//     },
    
//     async openChat(userId, userName) {
//         this.currentChatUserId = userId;
    
//         // Update chat header
//         const chatUserName = document.getElementById('chat-user-name');
//         const chatUserStatus = document.getElementById('chat-user-status');
        
//         if (chatUserName) chatUserName.textContent = userName;
//         if (chatUserStatus) chatUserStatus.textContent = 'Online'; // Update dynamically
    
//         // Show chat main section
//         const chatMain = document.getElementById('chat-main');
//         if (chatMain) chatMain.classList.remove('hidden');
    
//         // Fetch message history
//         const messages = await this.fetchMessages(userId);
//         this.renderMessages(messages);
    
//         // Mark messages as read
//         this.markMessagesAsRead(userId);
//     },
    
//     async fetchMessages(userId) {
//         try {
//             const response = await api.fetchMessages(userId);
//             if (response.success) {
//                 return response.messages;
//             } else {
//                 logger.error('Failed to fetch messages:', response.message);
//                 return [];
//             }
//         } catch (error) {
//             logger.error('Error fetching messages:', error);
//             return [];
//         }
//     },
    
//     renderMessages(messages) {
//         const chatMessages = document.getElementById('chat-messages');
//         if (!chatMessages) return;
        
//         chatMessages.innerHTML = ''; // Clear existing messages
    
//         messages.forEach(message => {
//             const messageElement = document.createElement('div');
//             messageElement.className = `message ${message.senderId === currentUserId ? 'sent' : 'received'}`;
//             messageElement.innerHTML = `
//                 <div class="message-content">${message.content}</div>
//                 <div class="message-timestamp">${new Date(message.timestamp).toLocaleTimeString()}</div>
//             `;
//             chatMessages.appendChild(messageElement);
//         });
    
//         // Scroll to bottom
//         chatMessages.scrollTop = chatMessages.scrollHeight;
//     },
    
//     async markMessagesAsRead(userId) {
//         try {
//             await api.markMessagesAsRead(userId);
            
//             // Send read receipt via WebSocket
//             webSocketManager.sendMessage('read_receipt', {
//                 reader_id: currentUserId,
//                 sender_id: userId
//             });
//         } catch (error) {
//             logger.error('Error marking messages as read:', error);
//         }
//     },
    
//     handleMessageSubmit(e) {
//         e.preventDefault();
    
//         const input = document.getElementById('chat-input');
//         if (!input) return;
        
//         const content = input.value.trim();
    
//         if (content && this.currentChatUserId) {
//             // Send message via WebSocket
//             this.sendPrivateMessage(this.currentChatUserId, content);
    
//             // Clear input
//             input.value = '';
//         }
//     },
    
//     sendPrivateMessage(receiverId, content) {
//         // Send via WebSocket
//         const messageSent = webSocketManager.sendMessage('private_message', {
//             receiver_id: receiverId,
//             content: content
//         });
        
//         // If WebSocket failed, send via API as fallback
//         if (!messageSent) {
//             api.sendMessage(receiverId, content)
//                 .then(response => {
//                     if (response.success) {
//                         this.addNewMessage(response.message);
//                     }
//                 })
//                 .catch(error => {
//                     logger.error('Failed to send message via API:', error);
//                 });
//         }
//     },
    
//     addNewMessage(message) {
//         // Only add if currently chatting with this user
//         if (this.currentChatUserId !== message.sender_id && this.currentChatUserId !== message.receiver_id) {
//             // Update unread count on user list instead
//             this.updateUnreadCount(message.sender_id);
//             return;
//         }
        
//         const chatMessages = document.getElementById('chat-messages');
//         if (!chatMessages) return;
        
//         const messageElement = document.createElement('div');
//         const isSent = message.sender_id === currentUserId;
        
//         messageElement.className = `message ${isSent ? 'sent' : 'received'}`;
//         messageElement.innerHTML = `
//             <div class="message-content">${message.content}</div>
//             <div class="message-timestamp">${new Date(message.timestamp).toLocaleTimeString()}</div>
//         `;
        
//         chatMessages.appendChild(messageElement);
        
//         // Scroll to bottom
//         chatMessages.scrollTop = chatMessages.scrollHeight;
        
//         // Mark as read if we received a message
//         if (!isSent && this.currentChatUserId) {
//             this.markMessagesAsRead(this.currentChatUserId);
//         }
//     },
    
//     handleTyping() {
//         if (!this.currentChatUserId) return;
        
//         // Clear existing timeout
//         if (this.typingTimeout) {
//             clearTimeout(this.typingTimeout);
//         }
        
//         // Send typing indicator
//         webSocketManager.sendMessage('typing_indicator', {
//             sender_id: currentUserId,
//             receiver_id: this.currentChatUserId,
//             typing: true
//         });
        
//         // Set timeout to stop typing indicator
//         this.typingTimeout = setTimeout(() => {
//             webSocketManager.sendMessage('typing_indicator', {
//                 sender_id: currentUserId,
//                 receiver_id: this.currentChatUserId,
//                 typing: false
//             });
//         }, 2000);
//     },
    
//     showTypingIndicator(data) {
//         if (data.sender_id !== this.currentChatUserId) return;
        
//         const typingIndicator = document.getElementById('typing-indicator');
//         if (!typingIndicator) return;
        
//         if (data.typing) {
//             typingIndicator.classList.remove('hidden');
//         } else {
//             typingIndicator.classList.add('hidden');
//         }
//     },
    
//     updateUserStatus(data) {
//         const userElement = document.querySelector(`.user[data-user-id="${data.user_id}"]`);
//         if (!userElement) return;
        
//         const statusElement = userElement.querySelector('.user-status');
//         if (statusElement) {
//             statusElement.className = `user-status ${data.online ? 'online' : 'offline'}`;
//             statusElement.textContent = data.online ? 'Online' : 'Offline';
//         }
        
//         // Update chat header if chatting with this user
//         if (this.currentChatUserId === data.user_id) {
//             const chatUserStatus = document.getElementById('chat-user-status');
//             if (chatUserStatus) {
//                 chatUserStatus.textContent = data.online ? 'Online' : 'Offline';
//             }
//         }
//     },
    
//     updateUnreadCount(userId) {
//         const userElement = document.querySelector(`.user[data-user-id="${userId}"]`);
//         if (!userElement) return;
        
//         let unreadElement = userElement.querySelector('.unread-count');
        
//         if (!unreadElement) {
//             unreadElement = document.createElement('span');
//             unreadElement.className = 'unread-count';
//             unreadElement.textContent = '1';
//             userElement.appendChild(unreadElement);
//         } else {
//             const currentCount = parseInt(unreadElement.textContent, 10) || 0;
//             unreadElement.textContent = (currentCount + 1).toString();
//         }
//     },
    
//     markMessageAsRead(data) {
//         // Update UI to show message has been read
//         const userElement = document.querySelector(`.user[data-user-id="${data.reader_id}"]`);
//         if (!userElement) return;
        
//         const unreadElement = userElement.querySelector('.unread-count');
//         if (unreadElement) {
//             unreadElement.remove();
//         }
//     },
// };

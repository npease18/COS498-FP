class ChatManager {
    constructor(db, sm, sockman, app) {
        this.db = db;
        this.sessionManager = sm;
        this.socketManager = sockman;
        this.app = app;
        
        this.initChatHandlers();
        this.initChatAPI();
    }

    initChatHandlers() {
        this.socketManager.io.on("connection", async (socket) => {
            // Extract Session
            const sessionId = socket.handshake.headers.cookie.split('session=')[1].substring(0, 40);

            const session = await this.sessionManager.validateSession(sessionId);

            if (!session) {
                socket.emit("auth_error", { message: "Authentication failed. Please log in again." });
                socket.disconnect();
                return;
            }

            socket.on("new_message", async (data) => this.newMessage(session, data) );
        });
    }

    initChatAPI() {
        // Load existing chat messages API
        this.app.get('/api/chat/history', async (req, res) => this.getChatHistory(req, res) );
        this.app.post('/api/chat/new', async (req, res) => this.newMessageAPI(req, res) );
    }

    // API Handlers
    async getChatHistory(req, res) {
        // Verify Session
        const sessionId = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        // Grabbing the last 50 chats
        const getChatsQuery = `
            SELECT chats.username, content, chats.created_at, users.display_name, users.avatarColor
            FROM chats
            LEFT JOIN users ON chats.username = users.username
            ORDER BY chats.created_at ASC
            LIMIT 50
        `;

        const chats = await this.db.queryAll(getChatsQuery);

        const chatMessages = chats.map(chat => new ChatMessage(chat));

        return res.json({ success: true, messages: chatMessages });
    }

    // Fairly redundant with socket version, but requested in project specs
    // TODO: send Troy an email about this
    async newMessageAPI(req, res) {
        // Verify Session
        const sessionId = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const data = req.body.message;
        if (data.trim().length > 50 || data.trim().length == 0) {
            return res.status(400).json({ success: false, message: 'Message must be between 1 and 50 characters' });
        }

        const message = new ChatMessage(data, new Date(), session);

        const addChatToDB = `
            INSERT INTO chats (username, content, created_at)
            VALUES (?, ?, ?)
        `

        await this.db.execute(addChatToDB, [session.username, message.content, message.createdAt.toISOString()]);

        this.emitMessage(message);

        return res.json({ success: true, message: 'Message sent' });
    }

    // Socket Chat Handlers
    async newMessage(session, data) {
        // Validate session is still valid
        const validSession = await this.sessionManager.validateSession(session.session_id);
        if (!validSession) {
            return; // Do nothing, client should already process this
        }

        if (data.trim().length > 50 || data.trim().length == 0) {
            return; // Do nothing, client should already process this
        }

        const message = new ChatMessage(data, new Date(), session);

        const addChatToDB = `
            INSERT INTO chats (username, content, created_at)
            VALUES (?, ?, ?)
        `

        await this.db.execute(addChatToDB, [session.username, message.content, message.createdAt.toISOString()]);

        this.emitMessage(message);
    }

    async emitMessage(message) {
        this.socketManager.io.emit("message", message);
    }
}

class ChatMessage {
    constructor(chat, createdAt=null, session=null) {
        if (chat && createdAt === null && session === null) {
            this.construct_from_db(chat);
        } else if (createdAt !== null && session !== null) {
            this.construct_from_self(chat, createdAt, session);
        }
    }

    // For when we pass a chat from DB
    construct_from_db(chat) {
        this.display_name = chat.display_name;
        this.content = chat.content;
        this.createdAt = new Date(chat.created_at);
        this.avatarInitial = chat.username.charAt(0).toUpperCase();
        this.avatarColor = chat.avatarColor;
    }

    // For when we create a new chat message ourselves
    construct_from_self(content, createdAt, session) {
        this.display_name = session.display_name;
        this.content = content;
        this.createdAt = createdAt;
        this.avatarInitial = session.username.charAt(0).toUpperCase();
        this.avatarColor = session.avatarColor;
    }
}

export default ChatManager;

// Chat Manager
// Handles real-time chat functionality via WebSockets

// Imports
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

class ChatManager {
    constructor(sockman, db, sm) {
        this.db = db;
        this.sessionManager = sm;
        this.socketManager = sockman;
        
        this.initChatHandlers();
    }

    // Sets up the chat socket handler functions
    // Security: Validates user sessions on connection
    initChatHandlers = () => {
        this.socketManager.io.on("connection", async (socket) => {
            // Extract Session
            const sessionId = socket.handshake.headers.cookie.split('session=')[1].substring(0, 40);

            const session = await this.sessionManager.validateSession(sessionId);

            // Validate there is a authorized user
            if (!session) {
                socket.emit("auth_error", { message: "Authentication failed. Please log in again." });
                socket.disconnect();
                return;
            }

            // Send historical messages to client
            socket.on("history", async (data) => this.sendHistoricalMessages(socket) );

            // Wait for new messages
            socket.on("new_message", async (data) => this.newMessage(session, data) );
        });
    }

    // Socket Chat Handlers

    // Handles a new chat message from a client
    // Security: Validates session is still valid before processing message
    newMessage = async (session, data) => {
        // Validate session is still valid
        const validSession = await this.sessionManager.validateSession(session.session_id);
        if (!validSession) {
            return; // Bomb out
        }

        // Somehow a bad message come down
        if (data.trim().length > 50 || data.trim().length == 0) {
            return; // Bomb out
        }

        // Build a new message, save it, and yeet it back to the clients
        const message = new ChatMessage(data, new Date(), session);
        await this.db.execute(SharedDatabaseQueries.Chat.addChatQuery, [session.username, message.content, message.createdAt.toISOString()]);
        this.emitMessage(message);
    }

    // Handles sending historical messages to the newly connected client
    // Security: Since this is only sending past messages, and session validation is done on connection, no further validation is needed here
    sendHistoricalMessages = async (socket) => {
        // Get last 50 messages from DB
        const chats = await this.db.queryAll(SharedDatabaseQueries.Chat.getLast50ChatsQuery);

        // Sending one at a time allows us to use regular message parsing behavior on the client
        for (const chat of chats) {
            const chatMessage = new ChatMessage(chat);
            socket.emit("message", chatMessage);
        }
    }

    // Emits a chat message to all connected clients
    emitMessage = async (message) => {
        this.socketManager.io.emit("message", message);
    }
}

// Chat Message Class
// Properly structures the chat message object for transmission to clients
class ChatMessage {
    // Really miss the overloaded constructors from C#, but this will do
    constructor(chat, createdAt=null, session=null) {
        if (chat && createdAt === null && session === null) {
            this.construct_from_db(chat);
        } else if (createdAt !== null && session !== null) {
            this.construct_from_self(chat, createdAt, session);
        }
    }

    // For when we pass a chat from DB
    construct_from_db(chat) {
        this.username = chat.username;
        this.display_name = chat.display_name;
        this.content = chat.content;
        this.createdAt = new Date(chat.created_at);
        this.avatarInitial = chat.display_name.charAt(0).toUpperCase();
        this.avatarColor = chat.avatarColor;
    }

    // For when we create a new chat message ourselves
    construct_from_self(content, createdAt, session) {
        this.username = session.username;
        this.display_name = session.display_name;
        this.content = content;
        this.createdAt = createdAt;
        this.avatarInitial = session.display_name.charAt(0).toUpperCase();
        this.avatarColor = session.avatarColor;
    }
}

export default ChatManager;

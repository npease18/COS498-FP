// Session Manager
// Handles user session creation, validation, and deletion

// Imports
import EncryptionManager from "./EncryptionManager.js";
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

class SessionManager {
    constructor(app, db) {
        this.app = app;
        this.db = db;
    }

    // Create a new session for a given username
    addSession = (username) => {
        let sessionId = `session-${EncryptionManager.generateRandomToken(16)}`;
        this.db.execute(SharedDatabaseQueries.Session.addSessionQuery, [sessionId, username]);
        return sessionId;
    }

    // Delete a session by session ID
    deleteSession = (sessionId, res) => {
        this.db.execute(SharedDatabaseQueries.Session.removeSessionBySessionIDQuery, [sessionId]);
        res.clearCookie('session');
    }

    // Validate a session by session ID
    validateSession = async (sessionId) => {
        return await this.db.queryGet(SharedDatabaseQueries.Session.getSessionQuery, [sessionId]);
    }

    // Invalidate all sessions for a given username
    invalidateUserSessions = async (username) => {
        await this.db.execute(SharedDatabaseQueries.Session.removeSessionByUsernameQuery, [username]);
    }

    // Add session cookie to response
    addSessionCookie = (res, sessionId) => {
        res.cookie('session', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
    }

}

export default SessionManager;
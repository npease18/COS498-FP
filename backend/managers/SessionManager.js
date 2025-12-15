import EncryptionManager from "./EncryptionManager.js";

class SessionManager {
    constructor(app, db) {
        this.app = app;
        this.db = db;
    }

    // Helper Functions
    addSession(username) {
        let sessionId = `session-${EncryptionManager.generateRandomToken(16)}`;

        const sessionCreateQuery = `
            INSERT INTO sessions (session_id, username)
            VALUES (?, ?)
        `;

        this.db.execute(sessionCreateQuery, [sessionId, username]);

        return sessionId;
    }

    async validateSession(sessionId) {
        const sessionLookupQuery = `
            SELECT *
            FROM sessions
            LEFT JOIN users ON sessions.username = users.username
            WHERE session_id = ?
        `

        let isValid = await this.db.queryGet(sessionLookupQuery, [sessionId]);

        return isValid;
    }

    deleteSession(sessionId) {
        const sessionDeleteQuery = `
            DELETE FROM sessions
            WHERE session_id = ?
        `;

        this.db.execute(sessionDeleteQuery, [sessionId]);
    }

    async invalidateUserSessions(username) {
        const userSessionsDeleteQuery = `
            DELETE FROM sessions
            WHERE username = ?
        `;

        await this.db.execute(userSessionsDeleteQuery, [username]);
    }

}

export default SessionManager;
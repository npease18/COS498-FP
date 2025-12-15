import EncryptionManager from "./EncryptionManager.js";
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

class SessionManager {
    constructor(app, db) {
        this.app = app;
        this.db = db;
    }

    // Helper Functions
    addSession(username) {
        let sessionId = `session-${EncryptionManager.generateRandomToken(16)}`;

        this.db.execute(SharedDatabaseQueries.Session.addSessionQuery, [sessionId, username]);

        return sessionId;
    }

    async validateSession(sessionId) {
        console.log(SharedDatabaseQueries.Session)
        return await this.db.queryGet(SharedDatabaseQueries.Session.getSessionQuery, [sessionId]);
    }

    deleteSession(sessionId) {
        this.db.execute(SharedDatabaseQueries.Session.removeSessionBySessionIDQuery, [sessionId]);
    }

    // TODO: LOOK AND SEE IF NEEDED AWAIT
    async invalidateUserSessions(username) {
        await this.db.execute(SharedDatabaseQueries.Session.removeSessionByUsernameQuery, [username]);
    }

}

export default SessionManager;
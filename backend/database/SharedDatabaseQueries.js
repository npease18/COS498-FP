// Shared Database Queries (Static)
// Centralized SQL queries for various database operations

//  Naming Convention:
//  Each query is grouped by its related area of software

//  Within each entity, queries are categorized by their operation type:
//  Section
//      Getters    - get*Query
//      Insertions - add*Query
//      Updaters   - *Query
//      Deleters   - remove*Query

class SharedDatabaseQueries {
    // Chat Related Queries
    static Chat = {
        // Getters
        getLast50ChatsQuery: `
            SELECT chats.username, content, chats.created_at, users.display_name, users.avatarColor
            FROM chats
            LEFT JOIN users ON chats.username = users.username
            ORDER BY chats.created_at ASC
            LIMIT 50`,

        // Insertions
        addChatQuery: `
            INSERT INTO chats (username, content, created_at)
            VALUES (?, ?, ?)`,

        // Updaters
        // Deleters
    }

    // Comments Related Queries
    static Comment = {
        // Getters
        getCommentsQuery : `
            SELECT users.username, users.display_name, users.avatarColor, content, comments.created_at
            FROM comments
            LEFT JOIN users ON comments.username = users.username
            ORDER BY comments.created_at DESC
            LIMIT ? OFFSET ?`,

        getCommentCountQuery : `
            SELECT COUNT(*) FROM comments;`,

        // Insertions
        addCommentQuery: `
            INSERT INTO comments (username, content)
            VALUES (?, ?)`,

        // Updaters
        // Deleters
    }

    // Login Attempts Queries
    static LoginAttempts = {
        // Getters
        getLoginAttemptsQuery: `
            SELECT login_attempts_since_successful FROM users
            WHERE username = ?;`,

        getLockoutTimeRemainingQuery: `
            SELECT lockout_until FROM users
            WHERE username = ?;`,

        // Insertions
        addLoginAttemptQuery: `
            INSERT INTO login_attempts (username, success, ip_address)
            VALUES (?, ?, ?);`,

        // Updaters
        resetLoginAttemptsQuery: `
            UPDATE users
            SET login_attempts_since_successful = 0
            WHERE username = ?;`,

        setLockoutQuery: `
            UPDATE users
            SET lockout_until = ?
            WHERE username = ?;`,

        incrementUserLoginAttemptsQuery: `
            UPDATE users
            SET login_attempts_since_successful = login_attempts_since_successful + 1
            WHERE username = ?;`
    }

    // Password Reset Related Queries
    static PasswordReset = {
        // Getters
        getPasswordResetQueryByToken : `
            SELECT username, expires_at
            FROM password_resets
            WHERE reset_token = ?;`,
        
        getPasswordResetQueryByUsername : `
            SELECT reset_token FROM password_resets 
            WHERE username = ? AND expires_at > datetime('now')`,
        
        // Insertions
        addResetTokenQuery : `
            INSERT INTO password_resets (username, reset_token, expires_at)
            VALUES (?, ?, ?);`,

        // Updaters
        changeUserPasswordQuery : `
            UPDATE users
            SET password_hash = ?
            WHERE username = ?;`,

        // Deleters
        removeAllPasswordResetsQuery : `
            DELETE FROM password_resets
            WHERE username = ?;`
    }

    // Session Related Queries
    static Session = {
        // Getters
        getSessionQuery : `
            SELECT *
            FROM sessions
            LEFT JOIN users ON sessions.username = users.username
            WHERE session_id = ?`,

        // Insertions
        addSessionQuery : `
            INSERT INTO sessions (session_id, username)
            VALUES (?, ?)`,

        // Updaters
        // Deleters
        removeSessionByUsernameQuery : `
            DELETE FROM sessions
            WHERE username = ?`,

        removeSessionBySessionIDQuery : `
            DELETE FROM sessions
            WHERE session_id = ?`
    }

    // User Related Queries
    static User = {
        // Getters
        getUserByUsernameQuery : `
            SELECT * FROM users WHERE username = ?;`,

        getUserByEmailQuery : `
            SELECT * FROM users WHERE email = ?;`,

        // Insertions
        addUserQuery: `
            INSERT INTO users (username, email, password_hash, display_name)
            VALUES (?, ?, ?, ?);`,

        // Updaters
        updateProfileQuery : `
            UPDATE users
            SET display_name = ?, email = ?, avatarColor = ?
            WHERE username = ?`,

        // Deleters
    }
    
}

export default SharedDatabaseQueries;
// User Manager
// Handles user profile management and related functionalities

// Imports
import EmailManager from "../email/EmailManager.js";
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

const DISPLAY_NAME_MAX_LENGTH = 20; // Max length for display names

class UserManager {
    constructor(app, db, sm, am) {
        this.app = app;
        this.db = db;
        this.sessionManager = sm;
        this.authManager = am;
        this.emailManager = new EmailManager();
        
        this.setupAPIs();
        this.setupMiddleware();
    }

    // Setup API Endpoints
    setupAPIs() {
        this.app.post('/api/profile/update', async (req, res) => this.updateProfile(req, res))
    }

    // Handles profile update requests
    updateProfile = async (req, res) => {
        const { display_name, email, current_password, avatar_color } = req.body;
        
        // Validate Session
        const sessionId = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionId);
        if (!session) {
            return res.status(401).render('login', { error: 'Please log in to update your profile.' });
        }

        // Validate display name length is within limits
        if (display_name.length > DISPLAY_NAME_MAX_LENGTH && display_name.length > 0) {
            return res.status(400).render('profile', { error: `Display name must be ${DISPLAY_NAME_MAX_LENGTH} characters or less.`, user: res.locals.user });
        }

        // Validate current password
        const isPasswordValid = await this.authManager.validate(current_password, session.username);
        if (!isPasswordValid) {
            return res.status(403).render('profile', { error: 'Incorrect password. Profile update failed.', user: res.locals.user });
        }

        await this.db.execute(SharedDatabaseQueries.User.updateProfileQuery, [display_name, email, avatar_color, session.username]);
        
        // Check if email was updated
        if (email && email !== session.email) {
            await this.sendConfirmationEmail(session.username, email);
        }

        return res.redirect('/profile');
    }

    // Setup middleware
    setupMiddleware() {
        this.app.use(this.addUserToContext);
    }

    // Middleware to add user info to response locals
    addUserToContext = async (req, res, next) => {
        // Check sessionId, and if that exists, validate session and add user info to res.locals
        const sessionId = req.cookies.session;
        if (sessionId) {
            const session = await this.sessionManager.validateSession(sessionId);
            if (session) {
                res.locals.user = {
                    profile_letter: session.display_name.charAt(0).toUpperCase(),
                    user_object: session,
                    sessionId: sessionId
                };
            }
        }

        next();
    }

    // Helpers

    // Builds and sends a confirmation email upon email change
    sendConfirmationEmail = async (username, newEmail) => {
        const subject = "Confirmation of Email Address Change";
        const emailContent = `
            <p>Dear ${username},</p>
            <p>Your email address has been updated to ${newEmail}.</p>
            <p>Best regards,<br/>Comment Corner Team</p>
        `;

        return await this.emailManager.sendEmail(newEmail, subject, emailContent);
    }

}

export default UserManager;

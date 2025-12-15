import EmailManager from "../email/EmailManager.js";

const DISPLAY_NAME_MAX_LENGTH = 20;

class UserManager {
    constructor(app, db, sm, am) {
        this.app = app;
        
        this.db = db;
        this.sessionManager = sm;
        this.authManager = am;
        this.emailManager = new EmailManager();
        
        this.setupUserAPIs()
    }

    setupUserAPIs() {
        this.app.post('/api/profile/update', async (req, res) => this.updateProfile(req, res))
    }

    async updateProfile(req, res) {
        const { display_name, email, current_password, avatar_color } = req.body;
        const sessionId = req.cookies.session;

        const session = await this.sessionManager.validateSession(sessionId);
        if (!session) {
            return res.status(401).render('login', { error: 'Please log in to update your profile.' });
        }

        if (display_name.length > DISPLAY_NAME_MAX_LENGTH) {
            return res.status(400).render('profile', { error: `Display name must be ${DISPLAY_NAME_MAX_LENGTH} characters or less.`, user: res.locals.user });
        }

        const isPasswordValid = await this.authManager.validate(current_password, session.username);
        if (!isPasswordValid) {
            return res.status(403).render('profile', { error: 'Incorrect password. Profile update failed.', user: res.locals.user });
        }

        const updateProfileQuery = `
            UPDATE users
            SET display_name = ?, email = ?, avatarColor = ?
            WHERE username = ?
        `;

        await this.db.execute(updateProfileQuery, [display_name, email, avatar_color, session.username]);
        
        // Check if email was updated
        if (email && email !== session.email) {
            await this.sendConfirmationEmail(session.username, email);
        }

        return res.redirect('/profile');
    }

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

const DISPLAY_NAME_MAX_LENGTH = 20;

class UserManager {
    constructor(app, db, sm, am) {
        this.app = app;
        
        this.db = db;
        this.sessionManager = sm;
        this.authManager = am;
        
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
            SET display_name = ?, email = ?, profile_color = ?
            WHERE username = ?
        `;

        try {
            await this.db.execute(updateProfileQuery, [display_name, email, avatar_color, session.username]);
            return res.redirect('/profile');
        } catch (error) {
            return res.render('profile', { error: 'Failed to update profile.', user: res.locals.user });
        }
    }
}

export default UserManager;

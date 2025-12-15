import { PasswordPolicyValidationCode, default as EncryptionManager } from './EncryptionManager.js';
import EmailManager from '../email/EmailManager.js';
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

const authedPaths = ['/comments', '/comments/new', '/profile', '/chat'];

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

class AuthenticationManager {
    constructor(app, sm, db) {
        this.app = app;
        this.sessionManager = sm;
        this.db = db;
        this.emailManager = new EmailManager();

        this.setupAuthMiddleware();
        this.setupAuthAPIs();
    }

    // Setups
    setupAuthAPIs() {
        // API Routes
        this.app.post('/api/register', async (req, res) => {
            const { username, email, password } = req.body;

            const result = await this.registerUser(req, res);

            if (result.success) {
                res.cookie('session', this.sessionManager.addSession(username), {
                    httpOnly: true,
                    secure: false, // Set to true in production with HTTPS
                    sameSite: 'lax',
                    maxAge: 24 * 60 * 60 * 1000 // 24 hours
                });
                res.redirect('/comments');
            } else {
                return res.render('register', {
                    error: result.message,
                    username: username,
                    email: email
                });
            }
        });

        this.app.post('/api/login', async (req, res) => {
            const { username, password } = req.body;

            const result = await this.login(req, res);

            if (result.success) {
                // Set session cookie and redirect on success
                res.cookie('session', this.sessionManager.addSession(username), {
                    httpOnly: true,
                    secure: false, // Set to true in production with HTTPS
                    sameSite: 'lax',
                    maxAge: 24 * 60 * 60 * 1000 // 24 hours
                });
                res.redirect('/comments');
            } else {
                // Render login page with error on failure
                return res.render('login', {
                    error: result.message,
                    username: username
                });
            }
        });

        this.app.post('/api/logout', async (req, res) => this.logout(req, res));

        this.app.post('/api/change-password', async (req, res) => this.changePW(req, res));

        this.app.post('/api/forgot-password', async (req, res) => this.forgotPassword(req, res));

        this.app.post('/api/reset-password', async (req, res) => this.resetPassword(req, res));
    }

    setupAuthMiddleware() {
        this.app.use(this.requireAuth);
        this.app.use(this.addUserToContext);
        this.app.use(this.newPasswordTokenCheck);
    }

    // Middleware

    // Insert User Data into res.locals
    // todo: move to user manager
    addUserToContext = async (req, res, next) => {
        const sessionId = req.cookies.session;

        if (sessionId) {
            const session = await this.sessionManager.validateSession(sessionId);
            if (session) {
                res.locals.user = {
                    profile_letter: session.username.charAt(0).toUpperCase(),
                    user_object: session,
                    sessionId: sessionId
                };
            }
        }

        next();
    }

    // Require Authentication for Certain Pages
    requireAuth = async (req, res, next) => {
        const sessionId = req.cookies.session;

        if (!authedPaths.includes(req.path)) {
            next();
            return;
        }

        if (sessionId && await this.sessionManager.validateSession(sessionId)) {
            next();
        } else {
            res.redirect('/login');
        }
    }

    // Validate Reset Password Token Exists / Valid
    newPasswordTokenCheck = async (req, res, next) => {
        if (req.path === '/reset-password') {
            const { token } = req.query;

            if (!token) {
                return res.render('reset-password', {
                    validToken: false,
                    error: 'Invalid reset token'
                });
            }

            const resetRecord = await this.db.queryGet(SharedDatabaseQueries.PasswordReset.getPasswordResetQueryByToken, [token]);

            if (!resetRecord || resetRecord.used || new Date() > new Date(resetRecord.expires_at)) {
                return res.render('reset-password', {
                    validToken: false,
                    error: 'Invalid or expired reset token'
                });
            } else {
                next();
            }
        } else {
            next();
        }
    }

    // Base Functions
    async registerUser(req, res) {
        const { username, email, password } = req.body;

        const passwordValidationCode = await EncryptionManager.validatePasswordPolicy(password);
        if (passwordValidationCode !== PasswordPolicyValidationCode.VALID) {
            return { success: false, message: passwordValidationCode };
        }

        const hashedPassword = await EncryptionManager.encryptPassword(password);

        try {
            await this.db.execute(SharedDatabaseQueries.User.addUserQuery, [username, email, hashedPassword, username]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, true, req.headers['x-real-ip']]); // Technically counts as a login
            return { success: true };
        } catch (error) {
            return { success: false, message: 'Username or email already exists' };
        }
    }

    async login(req, res) {
        const { username, password } = req.body;

        const login_attempts = await this.db.queryGet(SharedDatabaseQueries.LoginAttempts.getLoginAttemptsQuery, [username]);
        const endTime = await this.db.queryGet(SharedDatabaseQueries.LoginAttempts.getLockoutTimeRemainingQuery, [username]);

        // First, check if in timeout
        if (new Date() < new Date(endTime.lockout_until)) {
            return { success: false, message: 'Account locked due to too many failed login attempts. Please try again later.' };
        }

        // Not in timeout, proceed with login
        const user = await this.db.queryGet(SharedDatabaseQueries.User.getUserByUsernameQuery, [username]);
        if (user && await EncryptionManager.verifyPassword(user.password_hash, password)) {
            // Good to login, log and reset failures if any
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, true, req.headers['x-real-ip']]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.setLockoutQuery, [null, username]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.resetLoginAttemptsQuery, [username]);
            await this.db.execute(SharedDatabaseQueries.removeAllPasswordResetsQuery, [username]);
            return { success: true, user: user };
        } else {
            // Not good, log failure and increment attempts
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, false, req.headers['x-real-ip']]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.incrementUserLoginAttemptsQuery, [username]);
            if (login_attempts.login_attempts_since_successful + 1 >= MAX_LOGIN_ATTEMPTS) {
                const lockoutUntil = new Date();
                lockoutUntil.setMinutes(lockoutUntil.getMinutes() + LOCKOUT_DURATION_MINUTES);
                await this.db.execute(SharedDatabaseQueries.LoginAttempts.setLockoutQuery, [lockoutUntil.toISOString(), username]);
            }
            return { success: false, message: 'Invalid username or password' };
        }
    }

    async logout(req, res) {
        const sessionId = req.cookies.session;
        if (sessionId && this.sessionManager.validateSession(sessionId)) {
            this.sessionManager.deleteSession(sessionId);
        }
        res.clearCookie('session', {
            httpOnly: true,
            secure: false, // Set to true in production with HTTPS
            sameSite: 'lax'
        });
        res.redirect('/');
    }

    async changePW(req, res) {
        const { current_password, new_password } = req.body;
        const sessionId = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionId);

        if (!session) {
            return res.render('profile', { error: 'No valid session', user: res.locals.user });
        }

        if (await this.validate(current_password, session.username) == true) {
            const passwordValidationCode = await EncryptionManager.validatePasswordPolicy(new_password);
            if (passwordValidationCode !== PasswordPolicyValidationCode.VALID) {
                return res.render('profile', { error: passwordValidationCode, user: res.locals.user });
            }

            const hashedPassword = await EncryptionManager.encryptPassword(new_password);

            try {
                await this.db.execute(SharedDatabaseQueries.PasswordReset.changeUserPasswordQuery, [hashedPassword, session.username]);
                await this.sessionManager.invalidateUserSessions(session.username);
                return res.redirect('/login');
            } catch (error) {
                return res.render('profile', { error: 'Failed to change password', user: res.locals.user });
            }
        } else {
            return res.render('profile', { error: 'Current password is incorrect', user: res.locals.user });
        }
    }

    forgotPassword = async (req, res) => {
        const { email } = req.body;
        const resettingUser = await this.db.queryGet(SharedDatabaseQueries.User.getUserByEmailQuery, [email]);

        if (!resettingUser) {
            // Immediately return success
            return res.render('forgot-password', {
                success: 'If an account with that email exists, a password reset link is on the way',
                email: email
            });
        }

        // Check for existing reset token
        const existingReset = await this.db.queryGet(SharedDatabaseQueries.getPasswordResetQueryByUsername, [resettingUser.username]);
        if (existingReset) {
            return res.render('forgot-password', {
                success: 'A password reset link has already been sent to your email. Please check your inbox.',
                email: email
            });
        }

        const resetToken = EncryptionManager.generateRandomToken(16);
        const expiresAt = new Date().setHours(new Date().getHours() + 1); // Expires in 1 hour
        
        // TODO: CLEAR OUT UNUSED ONES IF EXPIRED, or if logged in successfully
        await this.db.execute(SharedDatabaseQueries.PasswordReset.addResetTokenQuery, [resettingUser.username, resetToken, expiresAt.toString()]);

        // Build the email
        const emailText = `
            Hello ${resettingUser.display_name} (@${resettingUser.username}),<br/><br/>
            Here is your requested password reset link:<br/>
            <a href="http://sswd.lax18.dev/reset-password?token=${resetToken}">Reset Password</a><br/>
            <br/>
            This link will expire in 1 hour. If you did not request this, please ignore this email.<br/>
            <br/>
            Best,
            Comment Corner Team
        `

        await this.emailManager.sendEmail(resettingUser.email, "Password Reset", emailText);

        return res.render('forgot-password', {
            success: 'A password reset link has already been sent to your email. Please check your inbox.',
            email: email
        });
    }

    async resetPassword(req, res) {
        const { token, password, confirmPassword } = req.body;

        if (!token) {
            return res.render('reset-password', {
                validToken: false,
                error: 'Invalid reset token'
            });
        }

        if (password !== confirmPassword) {
            return res.render('reset-password', {
                validToken: true,
                token: token,
                error: 'Passwords do not match'
            });
        }

        // Validate token
        const resetRecord = await this.db.queryGet(SharedDatabaseQueries.PasswordReset.getPasswordResetQueryByToken, [token]);

        if (!resetRecord) {
            return res.render('reset-password', {
                validToken: false,
                error: 'Invalid or expired reset token'
            });
        }

        // Really should not occur... but checking it anyway
        if (new Date() > new Date(resetRecord.expires_at)) {
            return res.render('reset-password', {
                validToken: false,
                error: 'This reset link has expired'
            });
        }

        // Validate password policy
        const passwordValidationCode = await EncryptionManager.validatePasswordPolicy(password);
        if (passwordValidationCode !== PasswordPolicyValidationCode.VALID) {
            return res.render('reset-password', {
                validToken: true,
                token: token,
                error: passwordValidationCode
            });
        }

        // Hash new password
        const hashedPassword = await EncryptionManager.encryptPassword(password);

        // Update password
        await this.db.execute(SharedDatabaseQueries.PasswordReset.changeUserPasswordQuery, [hashedPassword, resetRecord.username]);

        // Invalidate all existing sessions for this user
        await this.sessionManager.invalidateUserSessions(resetRecord.username);

        // Delete all reset tokens for this user
        await this.db.execute(SharedDatabaseQueries.PasswordReset.removeAllPasswordResetsQuery, [resetRecord.username]);

        // Redirect to login with success message
        res.redirect('/login?reset=success');
    }

    // Helpers
    async validate(current_password, username) {
        const user = await this.db.queryGet(SharedDatabaseQueries.User.getUserByUsernameQuery, [username]);
        if (user && await EncryptionManager.verifyPassword(user.password_hash, current_password)) {
            return true;
        } else {
            return false;
        }
    }

}

export default AuthenticationManager;
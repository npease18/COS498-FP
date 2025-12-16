// Authentication Manager
// This manager handles user authentication via login, logout, registration, password changes, and password resets.
// 
// It also includes middleware to protect certain routes and validate password reset tokens.

// Imports
import { PasswordPolicyValidationCode, default as EncryptionManager } from './EncryptionManager.js';
import EmailManager from '../email/EmailManager.js';
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";

// Constants
const authedPaths = ['/comments', '/comments/new', '/profile', '/chat'];     // Array of Paths Requiring Authentication
const MAX_LOGIN_ATTEMPTS = 5;                                                // Max Login Attempts Before Lockout
const LOCKOUT_DURATION_MINUTES = 15;                                         // Lockout Duration in Minutes

class AuthenticationManager {

    // Initializer for the Authentication Manager
    constructor(app, db, sm ) {
        this.app = app;
        this.sessionManager = sm;
        this.db = db;
        this.emailManager = new EmailManager();

        this.setupMiddleware();
        this.setupAPIs();
    }

    // Setup Middleware
    setupMiddleware = () => {
        this.app.use(this.requireAuth);
        this.app.use(this.newPasswordTokenCheck);
    }

    // Authentication Validator for Protected Routes
    // In order to protect routes, this is verfied before any actual page content is sent to the user
    requireAuth = async (req, res, next) => {
        const sessionId = req.cookies.session;

        // Skip if not a protected route
        if (!authedPaths.includes(req.path)) {
            next();
            return;
        }

        // Valid Session = Authed to Proceed
        if (sessionId && await this.sessionManager.validateSession(sessionId)) {
            next();
        } else {
            res.redirect('/login');
        }
    }

    // Validate Reset Password Token Exists / Valid
    // This middleware checks if the reset password token is valid before allowing access to the reset password page
    // This protects against invalid/expired tokens being used to access the reset password page
    newPasswordTokenCheck = async (req, res, next) => {
        // Only applies to reset password page
        if (req.path === '/reset-password') {
            const { token } = req.query;

            // No token is instant deny
            if (!token) {
                return res.render('reset-password', {
                    validToken: false,
                    error: 'Invalid reset token'
                });
            }

            const resetRecord = await this.db.queryGet(SharedDatabaseQueries.PasswordReset.getPasswordResetQueryByToken, [token]);

            // If the record is missing or expired, deny
            if (!resetRecord || new Date() > new Date(resetRecord.expires_at)) {
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

    // Setup API Routes
    setupAPIs() {
        this.app.post('/api/register', async (req, res) => this.registerUser(req, res));

        this.app.post('/api/login', async (req, res) => this.login(req, res));

        this.app.post('/api/logout', async (req, res) => this.logout(req, res));

        this.app.post('/api/change-password', async (req, res) => this.changePW(req, res));

        this.app.post('/api/forgot-password', async (req, res) => this.forgotPassword(req, res));

        this.app.post('/api/reset-password', async (req, res) => this.resetPassword(req, res));
    }

    // Register New User
    registerUser = async (req, res) => {
        const { username, email, password, displayName } = req.body;

        // Check if user/email already exists
        if (await this.doesUserExist(username, email)) {
            return res.render('register', {
                error: 'Registration failed. Username or email may already be in use.',
            });
        }

        // Check if password meets policy
        const passwordValidationCode = await EncryptionManager.validatePasswordPolicy(password);
        if (passwordValidationCode !== PasswordPolicyValidationCode.VALID) {
            return res.render('register', {
                error: 'Password does not meet complexity requirements.',
                message: passwordValidationCode,
            });
        }

        const hashedPassword = await EncryptionManager.encryptPassword(password);

        await this.db.execute(SharedDatabaseQueries.User.addUserQuery, [username, email, hashedPassword, displayName]);
        await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, true, req.headers['x-real-ip']]); // Technically counts as a login
        
        // Registered, go ahead and log in
        this.sessionManager.addSessionCookie(res, this.sessionManager.addSession(username));
        res.redirect('/comments');
    }

    // User Login
    login = async (req, res) => {
        const { username, password } = req.body;

        const user = await this.db.queryGet(SharedDatabaseQueries.User.getUserByUsernameQuery, [username]);

        // If user does not exist, fail
        if (!user) {
            return res.render('login', {
                error: "Invalid username or password",
                username: username
            });
        }

        const login_attempts = await this.db.queryGet(SharedDatabaseQueries.LoginAttempts.getLoginAttemptsQuery, [username]);
        const endTime = await this.db.queryGet(SharedDatabaseQueries.LoginAttempts.getLockoutTimeRemainingQuery, [username]);

        // First, check if in timeout
        if (endTime && new Date() < new Date(endTime)) {
            return { success: false, message: 'Account locked due to too many failed login attempts. Please try again later.' };
        }

        // Not in timeout, proceed with login
        if (user && await EncryptionManager.verifyPassword(user.password_hash, password)) {
            // Good to login, log and reset failures if any
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, true, req.headers['x-real-ip']]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.setLockoutQuery, [null, username]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.resetLoginAttemptsQuery, [username]);
            await this.db.execute(SharedDatabaseQueries.PasswordReset.removeAllPasswordResetsQuery, [username]);
            this.sessionManager.addSessionCookie(res, this.sessionManager.addSession(username));
            res.redirect('/comments');
        } else {
            // Not good, log failure and increment attempts
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.addLoginAttemptQuery, [username, false, req.headers['x-real-ip']]);
            await this.db.execute(SharedDatabaseQueries.LoginAttempts.incrementUserLoginAttemptsQuery, [username]);
            if (login_attempts.login_attempts_since_successful + 1 >= MAX_LOGIN_ATTEMPTS) {
                const lockoutUntil = new Date();
                lockoutUntil.setMinutes(lockoutUntil.getMinutes() + LOCKOUT_DURATION_MINUTES);
                await this.db.execute(SharedDatabaseQueries.LoginAttempts.setLockoutQuery, [lockoutUntil.toISOString(), username]);
            }
            return res.render('login', {
                error: "Invalid username or password",
                username: username
            });
        }
    }

    // User Logout
    logout = async (req, res) => {
        const sessionId = req.cookies.session;
        if (sessionId && this.sessionManager.validateSession(sessionId)) {
            this.sessionManager.deleteSession(sessionId, res);
        }
        res.redirect('/');
    }

    // Change Password
    // To ensure security, this invalidates all existing sessions upon a successful password change
    // This function is called while logged in, so it also verifies the user is currently signed in
    changePW = async (req, res) => {
        const { current_password, new_password } = req.body;
        const sessionId = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionId);

        // No valid session, bomb out
        if (!session) {
            return res.render('profile', { error: 'No valid session', user: res.locals.user });
        }

        // Check if valid current password
        if (await this.validate(current_password, session.username) == true) {
            // Check policy
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

    // Forgot Password
    // Sends password reset email if user/email exists
    forgotPassword = async (req, res) => {
        const { email } = req.body;
        const resettingUser = await this.db.queryGet(SharedDatabaseQueries.User.getUserByEmailQuery, [email]);

        if (!resettingUser) {
            // Immediately return success to mask that user does not exist
            return res.render('forgot-password', {
                success: 'If an account with that email exists, a password reset link is on the way',
                email: email
            });
        }

        // Check for existing reset token
        const existingReset = await this.db.queryGet(SharedDatabaseQueries.PasswordReset.getPasswordResetQueryByUsername, [resettingUser.username]);
        if (existingReset) {
            return res.render('forgot-password', {
                success: 'A password reset link has already been sent to your email. Please check your inbox.',
                email: email
            });
        }

        const resetToken = EncryptionManager.generateRandomToken(16);
        const expiresAt = new Date().setHours(new Date().getHours() + 1); // Expires in 1 hour
        
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

    // Reset Password
    // This validates the forgot password token is authentic and not expired before allowing any changes
    resetPassword = async (req, res) => {
        const { token, password, confirmPassword } = req.body;

        // If no token, bomb out
        if (!token) {
            return res.render('reset-password', {
                validToken: false,
                error: 'No reset token provided'
            });
        }

        // Check passwords match
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

    // Validate password matches hashed password for user
    validate = async (current_password, username) => {
        const user = await this.db.queryGet(SharedDatabaseQueries.User.getUserByUsernameQuery, [username]);
        if (user && await EncryptionManager.verifyPassword(user.password_hash, current_password)) {
            return true;
        } else {
            return false;
        }
    }

    // Determine if conflicting email/username exists
    doesUserExist = async (username, email) => {
        const userByUsername = await this.db.queryGet(SharedDatabaseQueries.User.getUserByUsernameQuery, [username]);
        const userByEmail = await this.db.queryGet(SharedDatabaseQueries.User.getUserByEmailQuery, [email]);

        return (userByUsername || userByEmail);
    }

}

export default AuthenticationManager;
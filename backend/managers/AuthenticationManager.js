import { PasswordPolicyValidationCode, default as EncryptionManager } from './EncryptionManager.js';

const authedPaths = ['/comments', '/comments/new'];

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

class AuthenticationManager {
    constructor(app, sm, db) {
        this.app = app;
        this.sessionManager = sm;
        this.db = db;

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
    }

    setupAuthMiddleware() {
        this.app.use(this.addUserToContext);
        this.app.use(this.requireAuth);
    }

    // Middleware

    // Insert User Data into res.locals
    addUserToContext = async (req, res, next) => {
        const sessionId = req.cookies.session;
        
        if (sessionId) {
            const session = await this.sessionManager.validateSession(sessionId);
            if (session) {
                res.locals.user = {
                    username: session.username,
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

    // Base Functions
    async registerUser(req, res) {
        const { username, email, password } = req.body;

        const addUserQuery = `
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?);
        `

        const passwordValidationCode = await EncryptionManager.validatePasswordPolicy(password);
        if (passwordValidationCode !== PasswordPolicyValidationCode.VALID) {
            let message = 'Password does not meet the required policy.';
            switch (passwordValidationCode) {
                case PasswordPolicyValidationCode.TOO_SHORT:
                    message = 'Password is too short.';
                    break;
                case PasswordPolicyValidationCode.MISSING_UPPERCASE:
                    message = 'Password must contain at least one uppercase letter.';
                    break;
                case PasswordPolicyValidationCode.MISSING_LOWERCASE:
                    message = 'Password must contain at least one lowercase letter.';
                    break;
                case PasswordPolicyValidationCode.MISSING_DIGIT:
                    message = 'Password must contain at least one digit.';
                    break;
                case PasswordPolicyValidationCode.MISSING_SPECIAL_CHAR:
                    message = 'Password must contain at least one special character.';
                    break;
            }
            return { success: false, message: message };
        }

        const hashedPassword = await EncryptionManager.encryptPassword(password);

        try {
            await this.db.execute(addUserQuery, [username, email, hashedPassword]);
            return { success: true };
        } catch (error) {
            return { success: false, message: 'Username or email already exists' };
        }
    }

    async login(req, res) {
        const { username, password } = req.body;

        const getUserQuery = `
            SELECT * FROM users WHERE username = ?;
        `;

        const logAttemptQuery = `
            INSERT INTO login_attempts (username, success, ip_address)
            VALUES (?, ?, ?);
        `;

        const getLoginAttemptsQuery = `
            SELECT login_attempts_since_successful FROM users
            WHERE username = ?;
        `;

        const resetLoginAttemptsQuery = `
            UPDATE users
            SET login_attempts_since_successful = 0
            WHERE username = ?;
        `;

        const setLockoutQuery = `
            UPDATE users
            SET lockout_until = ?
            WHERE username = ?;
        `;

        const getTimeRemainingQuery = `
            SELECT lockout_until FROM users
            WHERE username = ?;
        `;

        const setUserLoginAttemptsQuery = `
            UPDATE users
            SET login_attempts_since_successful = login_attempts_since_successful + 1
            WHERE username = ?;
        `;

        const login_attempts = await this.db.queryGet(getLoginAttemptsQuery, [username]);
        const endTime = await this.db.queryGet(getTimeRemainingQuery, [username]);

        // First, check if in timeout
        if (new Date() < new Date(endTime.lockout_until)) {
            console.log('Account locked until:', endTime.lockout_until);
            return { success: false, message: 'Account locked due to too many failed login attempts. Please try again later.' };
        }

        // Not in timeout, proceed with login

        try {
            const user = await this.db.queryGet(getUserQuery, [username]);
            if (user && await EncryptionManager.verifyPassword(user.password_hash, password)) {
                // Good to login, log and reset failures if any
                await this.db.execute(logAttemptQuery, [username, true, req.headers['x-real-ip']]);
                await this.db.execute(resetLoginAttemptsQuery, [username]);
                return { success: true, user: user };
            } else {
                // Not good, log failure and increment attempts
                await this.db.execute(logAttemptQuery, [username, false, req.headers['x-real-ip']]);
                await this.db.execute(setUserLoginAttemptsQuery, [username]);
                if (login_attempts.login_attempts_since_successful + 1 >= MAX_LOGIN_ATTEMPTS) {
                    const lockoutUntil = new Date();
                    lockoutUntil.setMinutes(lockoutUntil.getMinutes() + LOCKOUT_DURATION_MINUTES);
                    await this.db.execute(setLockoutQuery, [lockoutUntil.toISOString(), username]);
                }
                return { success: false, message: 'Invalid username or password' };
            }
        } catch (error) {
            console.error('Database error during login:', error);
            return { success: false, message: 'An error occurred during login' };
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

}

export default AuthenticationManager;
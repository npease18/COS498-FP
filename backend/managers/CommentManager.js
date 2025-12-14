class CommentManager {
    constructor(app, db, sm) {
        this.app = app;
        this.db = db;
        this.sessionManager = sm;

        this.setupCommentAPIs();
        this.setupMiddleware();
    }

    setupCommentAPIs() {
        this.app.post('/api/comments', async (req, res) => this.addComment(req, res));
    }

    setupMiddleware() {
        this.app.use(this.getComments);
    }

    addComment = async (req, res) => {
        const sessionToken = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionToken);
        if (!session) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const { content } = req.body
        
        const addCommentQuery = `
            INSERT INTO comments (username, content)
            VALUES (?, ?)
        `;
        try {
            await this.db.execute(addCommentQuery, [session.username, content]);
            res.redirect('/comments');
            return { success: true };
        } catch (error) {
            return { success: false, message: 'Failed to add comment' };
            res.redirect('/comments/new');
        }
    }

    getComments = async (req, res, next) => {
        if (req.path !== '/comments') {
            next();
            return;
        }

        const getCommentsQuery = `
            SELECT username, content, created_at
            FROM comments
            ORDER BY created_at DESC
        `;
        try {
            const comments = await this.db.queryAll(getCommentsQuery);
            res.locals.comments = comments.map(c => new Comment(c.username, c.content, c.created_at));
            next();
        } catch (error) {
            next(error);
        }
    }
}

class Comment {
    constructor(username, content, createdAt) {
        this.username = username;
        this.content = content;
        this.createdAt = createdAt;
        this.avatarInitials = username.charAt(0).toUpperCase();
    }
}


export default CommentManager;
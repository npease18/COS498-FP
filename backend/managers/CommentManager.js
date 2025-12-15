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
            res.redirect('/comments/new');
            return { success: false, message: 'Failed to add comment' };
        }
    }

    getComments = async (req, res, next) => {
        if (req.path !== '/comments') {
            next();
            return;
        }

        const getCommentsQuery = `
            SELECT users.display_name, users.avatarColor, content, comments.created_at
            FROM comments
            LEFT JOIN users ON comments.username = users.username
            ORDER BY comments.created_at DESC
        `;

        try {
            const comments = await this.db.queryAll(getCommentsQuery);
            res.locals.comments = comments.map(c => new Comment(c.display_name, c.content, c.created_at, c.avatarColor));
            next();
        } catch (error) {
            next(error);
        }
    }
}

class Comment {
    constructor(username, content, createdAt, avatarColor) {
        this.username = username;
        this.content = content;
        this.createdAt = createdAt;
        this.avatarInitials = username.charAt(0).toUpperCase();
        this.avatarColor = avatarColor;
    }
}


export default CommentManager;
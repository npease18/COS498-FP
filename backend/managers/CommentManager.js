const MAX_COMMENTS_PER_PAGE = 10;
const MAX_COMMENT_RENDER_LENGTH = 100;
const MAX_COMMENT_LENGTH = 1000;

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

        if (!content || content.length === 0 || content.length > MAX_COMMENT_LENGTH) {
            res.redirect('/comments/new');
            return { success: false, message: 'Invalid comment content' };
        }
        
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

        // If page number is provided, use it; otherwise default to 1
        const page = parseInt(req.query.page) || 1;

        // Get total count of comments
        const countQuery = `SELECT COUNT(*) FROM comments`;
        let countResult = await this.db.queryAll(countQuery);
        countResult = countResult[0]["COUNT(*)"];
        const totalComments = countResult;
        const totalPages = Math.ceil(totalComments / MAX_COMMENTS_PER_PAGE);

        const getCommentsQuery = `
            SELECT users.display_name, users.avatarColor, content, comments.created_at
            FROM comments
            LEFT JOIN users ON comments.username = users.username
            ORDER BY comments.created_at DESC
            LIMIT ? OFFSET ?
        `;

        const comments = await this.db.queryAll(getCommentsQuery, [MAX_COMMENTS_PER_PAGE, (page - 1) * MAX_COMMENTS_PER_PAGE]);
        res.locals.comments = comments.map(c => new Comment(c.display_name, c.content, c.created_at, c.avatarColor));
        
        // Add pagination info
        res.locals.pagination = {
            currentPage: page,
            totalPages: totalPages,
            totalComments: totalComments,
            hasNext: page < totalPages,
            hasPrev: page > 1,
            nextPage: page + 1,
            prevPage: page - 1
        };
        
        next();

    }
}

class Comment {
    constructor(username, content, createdAt, avatarColor) {
        this.username = username;
        this.content = content;
        this.createdAt = createdAt;
        this.avatarInitials = username.charAt(0).toUpperCase();
        this.avatarColor = avatarColor;
        
        // Add truncation logic for Read More functionality
        this.isLong = content.length > MAX_COMMENT_RENDER_LENGTH;
        this.truncatedContent = this.isLong ? content.substring(0, MAX_COMMENT_RENDER_LENGTH) + '...' : content;
        this.fullContent = content;
    }
}


export default CommentManager;
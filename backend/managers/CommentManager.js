// Comment Manager
// Handles comment functionality including adding and retrieving comments

// Imports
import SharedDatabaseQueries from "../database/SharedDatabaseQueries.js";
import MarkdownManager from "./MarkdownManager.js";

const MAX_COMMENTS_PER_PAGE = 10;       // Number of comments to show per page
const MAX_COMMENT_RENDER_LENGTH = 100;  // Length at which to truncate comments for "Read More"
const MAX_COMMENT_LENGTH = 1000;        // Max length of a comment

class CommentManager {
    constructor(app, db, sm) {
        this.app = app;
        this.db = db;
        this.sessionManager = sm;

        this.setupAPIs();
        this.setupMiddleware();
    }

    // Setup Middleware
    setupMiddleware = () => {
        this.app.use(this.getComments);
    }

    // Middleware to get comments for /comments route with pagination
    getComments = async (req, res, next) => {
        // Only process for /comments route
        if (req.path !== '/comments') {
            next();
            return;
        }

        // Extra redundancy, check if session is valid
        const sessionToken = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionToken);
        if (!session) {
            res.redirect('/login');
            return;
        }

        // If page number is provided, use it, otherwise default to 1
        const page = parseInt(req.query.page) || 1;

        // Get total count of comments
        let countResult = await this.db.queryAll(SharedDatabaseQueries.Comment.getCommentCountQuery);
        countResult = countResult[0]["COUNT(*)"];
        const totalComments = countResult;
        const totalPages = Math.ceil(totalComments / MAX_COMMENTS_PER_PAGE);

        // Grab the applicable comments and send it to the client
        const comments = await this.db.queryAll(SharedDatabaseQueries.Comment.getCommentsQuery, [MAX_COMMENTS_PER_PAGE, (page - 1) * MAX_COMMENTS_PER_PAGE]);
        res.locals.comments = comments.map(c => new Comment(c.username, c.display_name, c.content, c.created_at, c.avatarColor));
        
        // Create pagination object
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

    // Setup API Endpoints
    setupAPIs = () => {
        this.app.post('/api/comments', async (req, res) => this.addComment(req, res));
    }
    
    // Adds a new comment
    addComment = async (req, res) => {
        // Validate Session
        const sessionToken = req.cookies.session;
        const session = await this.sessionManager.validateSession(sessionToken);
        if (!session) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const { content } = req.body

        // If we got a bad comment, redirect back to new comment page
        if (!content || content.length === 0 || content.length > MAX_COMMENT_LENGTH) {
            res.redirect('/comments/new');
            return { success: false, message: 'Invalid comment content' };
        }
        
        // Add the comment to the database
        await this.db.execute(SharedDatabaseQueries.Comment.addCommentQuery, [session.username, content]);
        res.redirect('/comments');
    }
}

// Comment Class
// Contains extra (computed) properties for rendering comments properly on the frontend
class Comment {
    constructor(username, display_name, content, createdAt, avatarColor) {
        this.username = username;
        this.display_name = display_name;
        this.content = MarkdownManager.parseMarkdown(content);
        this.createdAt = createdAt;
        this.avatarInitials = display_name.charAt(0).toUpperCase();
        this.avatarColor = avatarColor;
        this.isLong = content.length > MAX_COMMENT_RENDER_LENGTH;
        this.truncatedContent = this.isLong ? content.substring(0, MAX_COMMENT_RENDER_LENGTH) + '...' : content;
        this.fullContent = content;
    }
}


export default CommentManager;
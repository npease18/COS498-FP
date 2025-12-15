import express from 'express';
import hbs from 'hbs';
import cookieParser from 'cookie-parser';

class RoutingManager {
    constructor() {
        this.app = express();

        this.setupMiddleware();
        this.setupHandlebars();
    }

    initRoutes() {
        this.setupRoutes();
    }

    setupRoutes() {
        // Page Routes
        this.app.get('/', (req, res) => res.render('home'));

        this.app.get('/login', (req, res) => {
            const resetSuccess = req.query.reset === 'success';
            res.render('login', { resetSuccess });
        });

        this.app.get('/register', (req, res) => res.render('register'));

        this.app.get('/profile', (req, res) => res.render('profile'));

        this.app.get('/comments', (req, res) => res.render('comments'));

        this.app.get('/comments/new', (req, res) => res.render('new-comment'));

        this.app.get('/chat', (req, res) => res.render('chat'));

        this.app.get('/forgot-password', (req, res) => res.render('forgot-password'));

        this.app.get('/reset-password', (req, res) => {
            const token = req.query.token;
            if (!token) {
                return res.render('reset-password', { 
                    validToken: false, 
                    error: 'No reset token provided' 
                });
            }
            res.render('reset-password', { 
                validToken: true, 
                token: token 
            });
        });
    }

    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser()); 

        this.app.use(express.static('../public'));
    }

    setupHandlebars() {
        // Handlebars
        this.app.set('view engine', 'hbs');
        this.app.set('views', '../views');

        // Register partials directory
        hbs.registerPartials('../partials');
    }
}

export default RoutingManager;
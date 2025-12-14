import express from 'express';
import hbs from 'hbs';
import cookieParser from 'cookie-parser';

class RoutingManager {
    constructor(db) {
        this.app = express();
        this.db = db;

        this.setupMiddleware();
        this.setupHandlebars();
    }

    initRoutes() {
        this.setupRoutes();
    }

    setupRoutes() {
        // Page Routes
        this.app.get('/', (req, res) => {
            res.render('home');
        });

        this.app.get('/login', (req, res) => {
            res.render('login');
        });

        this.app.get('/register', (req, res) => {
            res.render('register');
        });

        this.app.get('/comments', (req, res) => {
            res.render('comments');
        });

        this.app.get('/comments/new', (req, res) => {
            res.render('new-comment');
        });
    }

    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser()); 

        this.app.use(express.static('public'));
    }

    setupHandlebars() {
        // Handlebars
        this.app.set('view engine', 'hbs');
        console.log('PWD:', process.cwd());
        this.app.set('views', '../views');

        // Register partials directory
        hbs.registerPartials('../partials');
    }
}

export default RoutingManager;
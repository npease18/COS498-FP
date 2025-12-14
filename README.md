# COS498 Midterm Project: Server Side Programming Languages
## Link to Website: [https://sswd.lax18.dev/](https://sswd.lax18.dev/)

This is a midterm project for **COS498: Server Side Programming Languages** that demonstrates a full-stack web application using containerized microservices architecture with user authentication and a complete comment system.

## Project Overview

This project implements a complete comment-sharing web application with the following architecture:
- **Frontend**: Nginx serving static files and Handlebars templates
- **Backend**: Node.js/Express server with session management and authentication
- **Templating**: Handlebars with reusable partials for consistent UI
- **Authentication**: Session-based user registration and login system
- **Data Management**: In-memory storage for users, sessions, and comments
- **Containerization**: Docker containers orchestrated with Docker Compose

## Features

### User Authentication
- **User Registration**: Create new accounts with email and password confirmation
- **User Login**: Secure session-based authentication
- **Session Management**: Persistent login sessions with secure cookies
- **Error Handling**: Visual feedback for invalid credentials and registration errors

### Comment System
- **Browse Comments**: View all community discussions with filtering and sorting
- **Create Comments**: Authenticated users can post new comments
- **Interactive UI**: Inline comment form with toggle functionality
- **User Avatars**: Generated avatar initials for visual user identification

### User Interface
- **Responsive Design**: Mobile-friendly layout with consistent styling
- **Navigation**: Dynamic navigation based on authentication status
- **Visual Feedback**: Error messages, success states, and user guidance
- **Accessibility**: Proper ARIA labels and semantic HTML structure

## Prerequisites

Before running this project, ensure you have the following installed:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Project Structure

```
COS498-MTP/
├── docker-compose.yml          # Docker Compose configuration
├── README.md                   # This file
├── backend/
│   ├── Dockerfile             # Backend container configuration
│   └── server.js              # Node.js Express server with authentication
├── frontend/
│   ├── Dockerfile             # Frontend container configuration
│   └── default.conf           # Nginx configuration
├── views/                      # Handlebars templates
│   ├── home.hbs               # Homepage with project information
│   ├── login.hbs              # User sign-in page
│   ├── register.hbs           # User registration page
│   ├── comments.hbs           # Comments listing and creation
│   └── new-comment.hbs        # Standalone comment creation page
├── partials/                   # Reusable template components
│   ├── nav.hbs                # Navigation bar with auth state
│   ├── footer.hbs             # Site footer
│   ├── comment.hbs            # Individual comment display
│   └── new-comment-form.hbs   # Comment creation form
└── public/                     # Static assets
    ├── favicon.ico            # Site favicon
    ├── styles/
    │   └── main.css           # Stylesheet
    └── index.html             # Legacy static file
```

## How to Start the Webserver

### Option 1: Using Docker Compose (Recommended)

1. **Clone and navigate to the project directory:**
   ```bash
   cd /home/npease/COS498-MTP
   ```

2. **Start all services:**
   ```bash
   docker-compose up --build
   ```

3. **Access the application:**
   - Frontend: http://localhost
   - Comments page: http://localhost/comments
   - User registration: http://localhost/register
   - User login: http://localhost/login
   - Backend API: http://localhost/api/
   - Health check: http://localhost/api/health

4. **Stop the services:**
   ```bash
   docker-compose down
   ```

### Option 2: Manual Docker Build

1. **Build the backend:**
   ```bash
   docker build -t mtp-backend ./backend
   ```

2. **Build the frontend:**
   ```bash
   docker build -f frontend/Dockerfile -t mtp-frontend .
   ```

3. **Run the containers:**
   ```bash
   # Run backend
   docker run -d -p 3000:3000 --name backend mtp-backend
   
   # Run frontend
   docker run -d -p 80:80 --name frontend mtp-frontend
   ```

## API Endpoints

The backend provides the following API endpoints:

### Public Endpoints
- `GET /` - Homepage with project overview
- `GET /login` - User sign-in page
- `GET /register` - User registration page
- `GET /comments` - Comments listing page
- `GET /api/` - Welcome message with timestamp
- `GET /api/health` - Health check endpoint

### Authentication Endpoints
- `POST /api/register` - Create new user account
- `POST /api/login` - Authenticate user and create session
- `POST /api/logout` - Destroy user session and sign out

### Protected Endpoints
- `GET /comments/new` - Comment creation page (requires authentication)
- `POST /api/comments` - Create new comment (requires authentication)

## Architecture Details

### Frontend (Nginx + Handlebars)
- Serves static files from the `public/` directory
- Renders Handlebars templates with dynamic content
- Proxies API requests to the backend service
- Configured to strip `/api` prefix when forwarding to backend
- Responsive design with consistent styling across all pages

### Backend (Node.js/Express)
- REST API server running on port 3000
- Session-based authentication with secure cookies
- In-memory data storage for users, sessions, and comments
- Handlebars templating engine with partials support
- Comprehensive error handling and validation
- Cookie parser middleware for session management

### Authentication System
- **Registration**: Email/password with confirmation validation
- **Login**: Username/password with session creation
- **Session Management**: Secure HTTP-only cookies with expiration
- **Authorization**: Protected routes requiring authentication
- **Error Handling**: Visual feedback for authentication failures

### Template Architecture
- **Reusable Partials**: Navigation, footer, comments, and forms
- **Dynamic Navigation**: Different buttons based on auth state
- **Consistent Styling**: Shared CSS classes and inline styles
- **Error Display**: Template-based error messaging system

### Containerization
- Each service runs in its own Docker container
- Services communicate through Docker's internal network
- Frontend acts as a reverse proxy for API requests
- Persistent data stored in backend memory (resets on container restart)

## Development Notes

### Technical Implementation
- **Handlebars Templating**: Server-side rendering with reusable partials
- **Session Management**: Secure cookie-based authentication
- **Error Handling**: Template-based error display with form preservation
- **Responsive Design**: Mobile-friendly layout with consistent styling
- **Modular Architecture**: Separation of concerns between templates and logic

### Data Storage
- **In-Memory Storage**: Users, sessions, and comments stored in JavaScript objects
- **Session Security**: HTTP-only cookies with proper security settings
- **Data Persistence**: Data resets when backend container restarts
- **Future Enhancement**: Ready for database integration (MongoDB, PostgreSQL, etc.)

### UI/UX Features
- **Dynamic Navigation**: Auth state determines visible navigation options
- **Inline Comment Creation**: Toggle-able comment form on comments page
- **Form Validation**: Client-side required fields and server-side validation
- **Visual Feedback**: Error messages, success states, and loading indicators
- **Avatar Generation**: User initials displayed as visual avatars

### Security Considerations
- **Password Storage**: Plain text (development only - needs hashing for production)
- **Session Security**: Secure cookie settings with HTTP-only flag
- **CSRF Protection**: SameSite cookie policy for basic protection
- **Input Validation**: Server-side validation for all user inputs

## Course Information

**Course**: COS498 - Server Side Programming Languages  
**Project Type**: Midterm Project  
**Focus**: Demonstrating a complete full-stack web application with:
- Containerized microservices architecture
- Server-side templating and rendering
- User authentication and session management
- RESTful API design and implementation
- Database-like data management (in-memory)
- Responsive web design and user experience

## Future Enhancements

### Planned Improvements
- **Database Integration**: Replace in-memory storage with PostgreSQL or MongoDB
- **Password Security**: Implement bcrypt hashing for password storage
- **Enhanced Validation**: Add email verification and password strength requirements
- **Comment Features**: Add editing, deletion, and reply functionality
- **User Profiles**: Implement user profile pages and settings
- **Admin Features**: Add moderation tools and user management

### Production Readiness
- **HTTPS Support**: Enable SSL/TLS certificates for secure communication
- **Environment Variables**: Move configuration to environment-based settings
- **Error Logging**: Implement comprehensive logging and monitoring
- **Performance**: Add caching, CDN integration, and optimization
- **Testing**: Unit tests, integration tests, and end-to-end testing

## Troubleshooting

### Common Issues
1. **Port conflicts**: Ensure ports 80 and 3000 are available
2. **Docker issues**: Try `docker-compose down` and `docker-compose up --build`
3. **Permission issues**: Ensure Docker has proper permissions on your system
4. **API not responding**: Check that both containers are running with `docker-compose ps`
5. **Login issues**: Check browser console for session cookie errors
6. **Template errors**: Verify all partials are correctly registered and available

### Development Commands
```bash
# View container logs
docker-compose logs backend-nodejs
docker-compose logs frontend-nginx

# Restart services
docker-compose restart

# Rebuild and restart
docker-compose down && docker-compose up --build

# Check container status
docker-compose ps
```

### Data Reset
Since the application uses in-memory storage, all user accounts and comments will be lost when the backend container restarts. This is expected behavior for the development version.

## Author

Nicholas Pease  
COS498: Server Side Programming Languages
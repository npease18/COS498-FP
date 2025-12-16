# COS498 Final Project: Comment Corner
## Live Website: [https://sswd.lax18.dev/](https://sswd.lax18.dev/)

This is the final project for **COS498: Server Side Programming Languages** that demonstrates a comprehensive full-stack web application using modern containerized architecture with advanced security features, real-time chat functionality, and robust user management.

## Project Overview

Comment Corner is a complete social platform with sophisticated security implementations, featuring:

- **Frontend**: Nginx reverse proxy serving Handlebars templates and static assets
- **Backend**: Node.js/Express server with modular manager architecture
- **Database**: SQLite with comprehensive schema and relational integrity
- **Real-time Chat**: Socket.IO implementation with user authentication
- **Security**: Advanced authentication with rate limiting, password policies, and session management
- **Email Services**: Nodemailer integration for password resets and notifications
- **Containerization**: Multi-container Docker architecture with internal networking

## Features

### Advanced User Authentication & Security
- **Secure Registration**: Email validation, strong password policies, and display name customization
- **Multi-factor Login Protection**: Rate limiting with account lockouts after failed attempts
- **Session Management**: Secure HTTP-only cookies with automatic expiration
- **Password Reset Flow**: Email-based token system with expiration and security validation
- **Profile Management**: User can update display name, email, avatar color, and password
- **Security Logging**: Comprehensive login attempt tracking with IP address logging

### Real-time Chat System
- **Live Communication**: Socket.IO powered real-time messaging
- **User Authentication**: Chat access restricted to authenticated users only
- **Message History**: Persistent chat history with user avatars and timestamps
- **Responsive Interface**: Clean chat UI with real-time message display

### Advanced Comment System  
- **Markdown Support**: Rich text formatting with bold, italics, and HTML safety
- **Pagination**: Efficient comment browsing with page-based navigation
- **User Attribution**: Comments linked to user profiles with custom avatars
- **Content Management**: Character limits and content validation

### Professional User Interface
- **Responsive Design**: Mobile-first design with consistent styling across all devices
- **Dynamic Navigation**: Context-aware navigation based on authentication status
- **User Avatars**: Customizable color avatars with user initials
- **Accessibility**: Semantic HTML, ARIA labels, and keyboard navigation support

### Database & Data Management
- **SQLite Database**: Robust relational database with proper foreign key constraints
- **Data Integrity**: ACID transactions and referential integrity enforcement
- **Efficient Queries**: Optimized database queries with proper indexing
- **Backup & Recovery**: Database persistence across container restarts

## Prerequisites

Before running this project, ensure you have the following installed:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Environment Setup

### Required Environment Variables

Create a `.env` file in the `backend/email/` directory with your email service configuration:

```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_SENDER_EMAIL=your-email@gmail.com
EMAIL_ACCOUNT_PASSWORD=your-app-specific-password
```

### Email Service Configuration

The application uses Nodemailer for sending password reset emails. Supported email providers:

- **Gmail**: Use app-specific passwords (not your regular password)
- **Outlook/Hotmail**: Enable 2FA and generate app password
- **Yahoo**: Use app-specific passwords
- **Custom SMTP**: Any SMTP server with authentication

**Gmail Setup Example:**
1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password: Google Account → Security → App passwords
3. Use the 16-character app password in your `.env` file

## Project Structure

```
COS498-FP/
├── docker-compose.yml                 # Docker Compose configuration
├── README.md                          # Project documentation
├── backend/                           # Node.js backend application
│   ├── Dockerfile                     # Backend container configuration  
│   ├── package.json                   # Dependencies and scripts
│   ├── server.js                      # Application entry point
│   ├── database/                      # Database layer
│   │   ├── DBManager.js               # Database connection and query management
│   │   ├── schema.sql                 # Database schema definition
│   │   └── SharedDatabaseQueries.js   # Centralized SQL queries
│   ├── email/                         # Email service integration
│   │   └── EmailManager.js            # Nodemailer configuration and sending
│   └── managers/                      # Modular business logic managers
│       ├── AuthenticationManager.js   # User auth, login, registration
│       ├── ChatManager.js             # Real-time chat functionality  
│       ├── CommentManager.js          # Comment CRUD operations
│       ├── EncryptionManager.js       # Password hashing and validation
│       ├── MarkdownManager.js         # Text formatting and sanitization
│       ├── RoutingManager.js          # Express routing and middleware
│       ├── SessionManager.js          # Session creation and validation
│       ├── SocketManager.js           # WebSocket server configuration
│       └── UserManager.js             # User profile management
├── frontend/                          # Nginx frontend configuration
│   ├── Dockerfile                     # Frontend container setup
│   └── default.conf                   # Nginx reverse proxy configuration
├── views/                             # Handlebars page templates
│   ├── home.hbs                       # Homepage and landing page
│   ├── login.hbs                      # User authentication page
│   ├── register.hbs                   # User registration form
│   ├── comments.hbs                   # Comment browsing and creation
│   ├── new-comment.hbs                # Dedicated comment creation page
│   ├── profile.hbs                    # User profile management
│   ├── chat.hbs                       # Real-time chat interface
│   ├── forgot-password.hbs            # Password reset request
│   └── reset-password.hbs             # Password reset form
├── partials/                          # Handlebars reusable components
│   ├── nav.hbs                        # Dynamic navigation bar
│   ├── footer.hbs                     # Site footer
│   ├── comment.hbs                    # Individual comment display
│   └── ncf.hbs                        # New comment form component
└── public/                            # Static assets
    └── styles/                        # Public Style Sheets
        └── main.css                   # Application stylesheet
```

## Deployment Configurations

This application supports both **local development** and **production deployment** configurations using the same Docker Compose file with environment-based conditional services.

### Production Deployment (Current Live Site)

**Live Website**: [https://sswd.lax18.dev/](https://sswd.lax18.dev/)

The production deployment uses:
- **Newt Tunnel Service**: Routes external traffic through a reverse tunnel to expose the application publicly
- **Internal Networking**: All services communicate through Docker's internal network
- **No Direct Port Exposure**: The application is only accessible through the tunnel endpoint
- **Production Environment Variables**: `NODE_ENV=production`, tunnel credentials

**Production Services:**
- `backend-nodejs`: Node.js application server (no external ports)
- `proxy`: Nginx reverse proxy (no external ports)  
- `tunnel`: Newt tunnel client for public access via PANGOLIN endpoint

The tunnel service connects to a PANGOLIN endpoint (`https://vps.lax18.dev`) using credentials (`NEWT_ID` and `NEWT_SECRET`) to make the application publicly accessible without exposing local ports.

### Local Development Configuration

For local development and testing, the tunnel service should be disabled to allow direct localhost access.

**To run locally:**

1. **Disable the tunnel service** by commenting out the tunnel section in `docker-compose.yml`:
   ```yaml
   # tunnel:
   #   image: fosrl/newt
   #   container_name: newt
   #   restart: unless-stopped
   #   environment:
   #     - PANGOLIN_ENDPOINT=${PANGOLIN_ENDPOINT}
   #     - NEWT_ID=${NEWT_ID}
   #     - NEWT_SECRET=${NEWT_SECRET}
   #   depends_on:
   #     - proxy
   #   networks:
   #     - app-network
   ```

2. **Enable direct port access** by uncommenting the ports section in the proxy service:
   ```yaml
   proxy:
     # ... other configuration
     ports:
       - "80:80"  # Enable this line for local access
   ```

3. **Set development environment** in `.env`:
   ```env
   NODE_ENV=development
   PORT=3000
   ```

**Local Services:**
- `backend-nodejs`: Node.js application server
- `proxy`: Nginx reverse proxy with port 80 exposed to localhost
- `tunnel`: Disabled/commented out

## Setup and Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/npease18/COS498-FP.git
   cd COS498-FP
   ```

2. **Configure email services:**
   ```bash
   mkdir -p backend/email
   nano backend/email/.env
   # Add your email configuration (see Environment Setup section)
   ```

3. **Choose deployment mode:**

   **For Local Development:**
   ```bash
   # Edit docker-compose.yml to disable tunnel and enable proxy ports
   # Set NODE_ENV=development in .env
   docker-compose up --build
   ```

   **For Production Deployment:**
   ```bash
   # Ensure tunnel service is enabled and proxy ports are disabled
   # Set NODE_ENV=production and tunnel credentials in .env
   docker-compose up --build
   ```

4. **Access the application:**

   **Local Development:**
   - **Frontend**: http://localhost
   - **Chat**: http://localhost/chat  
   - **Comments**: http://localhost/comments
   - **User Registration**: http://localhost/register
   - **User Login**: http://localhost/login
   - **User Profiles**: http://localhost/profile

   **Production:**
   - **All Endpoints**: https://sswd.lax18.dev/

5. **Stop the services:**
   ```bash
   docker-compose down
   ```

## API Endpoints

### Public Routes
- `GET /` - Homepage with project overview
- `GET /login` - User sign-in page  
- `GET /register` - User registration page
- `GET /forgot-password` - Password reset request page
- `GET /reset-password?token=<token>` - Password reset form (requires valid token)

### Authentication API
- `POST /api/register` - Create new user account
  - **Body**: `{ username, email, password, displayName }`
  - **Validation**: Password policy enforcement, unique username/email
  - **Response**: Redirects to `/comments` or returns error

- `POST /api/login` - Authenticate user and create session
  - **Body**: `{ username, password }`
  - **Security**: Rate limiting, account lockout protection
  - **Response**: Sets session cookie, redirects to `/comments`

- `POST /api/logout` - Destroy user session and sign out
  - **Authentication**: Requires valid session
  - **Response**: Clears session cookie, redirects to `/`

- `POST /api/forgot-password` - Request password reset
  - **Body**: `{ email }`
  - **Process**: Sends reset email if account exists
  - **Security**: Rate limited, tokens expire in 1 hour

- `POST /api/reset-password` - Reset password with token
  - **Body**: `{ token, password, confirmPassword }`
  - **Validation**: Token validity, password policy compliance
  - **Security**: Invalidates all existing sessions

### Protected Routes (Requires Authentication)

- `GET /comments` - View all comments with pagination
- `GET /comments/new` - Comment creation page  
- `GET /profile` - User profile management page
- `GET /chat` - Real-time chat interface

### Protected API Endpoints

- `POST /api/comments` - Create new comment
  - **Body**: `{ content }`
  - **Validation**: 1000 character limit, markdown parsing
  - **Response**: Redirects to `/comments`

- `POST /api/profile/update` - Update user profile  
  - **Body**: `{ display_name, email, current_password, avatar_color }`
  - **Security**: Requires password confirmation
  - **Features**: Email change notifications

- `POST /api/change-password` - Change user password
  - **Body**: `{ current_password, new_password }`
  - **Security**: Invalidates all existing sessions
  - **Validation**: Password policy enforcement

### Chat API (WebSocket)

- **Connection**: Requires authenticated session cookie
- **Events**:
  - `history` - Request message history (last 50 messages)
  - `new_message` - Send chat message (50 character limit)
  - `message` - Receive chat message broadcast
  - `auth_error` - Authentication failure notification

## Database Schema

The application uses SQLite with the following relational schema:

### Users Table
```sql
CREATE TABLE users (
    id                              INTEGER     PRIMARY KEY AUTOINCREMENT,
    username                        CHAR(50)    UNIQUE NOT NULL,
    password_hash                   CHAR(255)   NOT NULL,      -- Argon2 hashed passwords
    email                           CHAR(100)   UNIQUE NOT NULL,
    display_name                    CHAR(100),
    lockout_until                   TIMESTAMP,                  -- Account lockout mechanism
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    avatarColor                     CHAR(7)     DEFAULT '#2b6cb0',
    login_attempts_since_successful INTEGER     DEFAULT 0
);
```

### Comments Table
```sql
CREATE TABLE comments (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    content                         TEXT        NOT NULL,
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username, created_at)         -- Composite primary key
);
```

### Sessions Table 
```sql
CREATE TABLE sessions (
    session_id                      CHAR(100)   PRIMARY KEY,   -- Random session tokens
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
);
```

### Login Attempts Table
```sql
CREATE TABLE login_attempts (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    attempt_time                    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    success                         BOOLEAN     NOT NULL,
    ip_address                      CHAR(45),                  -- Supports IPv4 and IPv6
    PRIMARY KEY (username, attempt_time, ip_address)
);
```

### Password Resets Table  
```sql
CREATE TABLE password_resets (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    reset_token                     CHAR(100)   UNIQUE NOT NULL,
    expires_at                      TIMESTAMP   NOT NULL,      -- 1-hour expiration
    PRIMARY KEY (username, reset_token)
);
```

### Chats Table
```sql
CREATE TABLE chats (
    chat_id                         INTEGER     PRIMARY KEY AUTOINCREMENT,
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    content                         CHAR(50)    NOT NULL,     -- 50 character limit
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
);
```

## Security Features Implemented

### Password Security
- **Argon2 Hashing**: Industry-standard password hashing with configurable parameters
- **Password Policy**: Enforced complexity requirements
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter  
  - At least one number
  - At least one special character (!@#$%^&*)
- **Password Reset**: Secure token-based password recovery with 1-hour expiration

### Session Security  
- **HTTP-Only Cookies**: Session tokens inaccessible to client-side JavaScript
- **Secure Cookie Settings**: HTTPS-only transmission in production
- **SameSite Policy**: CSRF attack prevention through strict same-site policy
- **Session Validation**: Every protected request validates session authenticity
- **Automatic Cleanup**: Invalid sessions automatically removed

### Rate Limiting & Account Protection
- **Login Attempt Limiting**: Maximum 5 failed attempts before lockout
- **Account Lockout**: 15-minute temporary lockout after failed attempts
- **IP Address Logging**: Track login attempts with source IP addresses

### Data Validation & Sanitization
- **Input Validation**: Server-side validation for all user inputs
- **SQL Injection Prevention**: Parameterized queries prevent SQL injection
- **XSS Protection**: HTML sanitization and content escaping
- **Content Limits**: Character limits prevent DoS attacks
- **Email Validation**: RFC-compliant email address validation

### Database Security
- **Foreign Key Constraints**: Referential integrity enforcement
- **Cascade Deletes**: Proper cleanup of related data
- **Prepared Statements**: SQL injection prevention

### Email Features:
- **Password Reset Emails**: Secure token-based password recovery links
- **Profile Change Notifications**: Automatic emails when email addresses are updated
- **HTML Email Templates**: Professional branded email formatting
- **Error Handling**: Graceful degradation when email services are unavailable

### Email Security:
- **Token Expiration**: All email links expire after 1 hour
- **One-time Use**: Reset tokens are invalidated after use
- **Rate Limiting**: Prevents email spam and abuse
- **Template Sanitization**: Prevents email injection attacks

## Architecture & Technology Stack

### Backend Architecture (Modular Manager Pattern)
- **Modular Design**: Business logic separated into specialized managers
- **Dependency Injection**: Managers receive dependencies through constructors
- **Single Responsibility**: Each manager handles one aspect of functionality
- **Scalable Structure**: Easy to add new features and modify existing ones

### Manager Responsibilities:
- **AuthenticationManager**: User registration, login, logout, password resets
- **SessionManager**: Session creation, validation, and cleanup
- **UserManager**: Profile management, email updates, user context
- **CommentManager**: Comment CRUD operations, pagination, markdown parsing
- **ChatManager**: Real-time messaging, WebSocket handling, message history
- **RoutingManager**: Express setup, middleware configuration, route definitions
- **SocketManager**: WebSocket server initialization and configuration
- **EncryptionManager**: Password hashing, validation, token generation
- **MarkdownManager**: Text formatting, sanitization, XSS prevention
- **DBManager**: Database connections, query execution, transaction management
- **EmailManager**: SMTP configuration, email sending, template rendering

### Frontend Architecture (Nginx + Handlebars)
- **Nginx Reverse Proxy**: Routes requests between static files and API endpoints
- **Server-Side Rendering**: Handlebars templates with dynamic data injection
- **Modular Templates**: Reusable partials for consistent UI components
- **Static Asset Serving**: Optimized delivery of CSS, JavaScript, and images

### Database Architecture
- **SQLite**: Lightweight, ACID-compliant relational database
- **Normalized Schema**: Proper foreign key relationships and constraints
- **Query Optimization**: Centralized queries in SharedDatabaseQueries class
- **Transaction Safety**: Proper error handling and rollback mechanisms

### Technology Stack:
- **Runtime**: Node.js 18+ with ES6 modules
- **Web Framework**: Express.js for HTTP server and middleware
- **Template Engine**: Handlebars for server-side rendering
- **Database**: SQLite3 with prepared statements
- **Real-time Communication**: Socket.IO for WebSocket connections
- **Email Service**: Nodemailer with SMTP support
- **Password Security**: Argon2 for cryptographically secure hashing
- **Session Management**: HTTP-only cookies with security headers
- **Reverse Proxy**: Nginx for production-ready request handling
- **Containerization**: Docker and Docker Compose for deployment

## Known Limitations and Issues

### Current Limitations:
1. **SQLite Concurrency**: Limited concurrent write operations
2. **In-memory Chat**: Chat history limited to 50 messages
3. **Email Dependency**: Password reset requires external SMTP configuration
4. **File Uploads**: No support for image or file attachments
5. **Mobile Optimization**: UI optimized for desktop, limited mobile testing

### Known Issues:
1. **Session Cleanup**: No automatic cleanup of expired sessions
2. **Rate Limiting**: Basic implementation without advanced throttling
3. **Error Logging**: Limited error tracking and monitoring
4. **Data Backup**: No automated backup mechanism for SQLite database
5. **Scalability**: Single-instance deployment without load balancing

### Browser Compatibility:
- **Supported**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **WebSocket Support**: Requires modern browser with Socket.IO compatibility
- **Cookie Support**: Requires third-party cookie support for sessions

### Performance Considerations:
- **Database Size**: Performance degrades with large numbers of users/comments
- **Memory Usage**: Chat history and sessions stored in memory
- **Concurrent Users**: Limited by single Node.js process
- **Asset Optimization**: No CDN or compression for static assets

## Author & Course Information

**Author**: Nicholas Pease  
**Course**: COS498 - Server Side Programming Languages  
**Institution**: University   of Maine
**Semester**: Fall 2025
**Project Type**: Final Project
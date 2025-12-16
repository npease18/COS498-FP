// Import Managers
import AuthenticationManager    from "./managers/AuthenticationManager.js";
import ChatManager              from "./managers/ChatManager.js";
import CommentManager           from "./managers/CommentManager.js";
import DBManager                from "./database/DBManager.js";
import RoutingManager           from "./managers/RoutingManager.js";
import SessionManager           from "./managers/SessionManager.js";
import SocketManager            from "./managers/SocketManager.js";
import UserManager              from "./managers/UserManager.js";

const PORT = process.env.PORT || 3000;

// Initialize Managers
let dbManager       = new DBManager                 ();
let routingManager  = new RoutingManager            ();
let socketManager   = new SocketManager             (routingManager.app);  
let sessionManager  = new SessionManager            (routingManager.app, dbManager);
let authManager     = new AuthenticationManager     (routingManager.app, dbManager, sessionManager);
let commentManager  = new CommentManager            (routingManager.app, dbManager, sessionManager);
let chatManager     = new ChatManager               (socketManager,      dbManager, sessionManager); 
let userManager     = new UserManager               (routingManager.app, dbManager, sessionManager, authManager);

// Gotta load the routes after all the middleware setup
routingManager.setupRoutes();

// Start server
socketManager.server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
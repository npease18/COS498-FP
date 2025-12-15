// Import Managers
import RoutingManager from "./managers/RoutingManager.js";
import AuthenticationManager from "./managers/AuthenticationManager.js";
import SessionManager from "./managers/SessionManager.js";
import DBManager from "./database/DBManager.js";
import CommentManager from "./managers/CommentManager.js";
import UserManager from "./managers/UserManager.js";
import SocketManager from "./managers/SocketManager.js";
import ChatManager from "./managers/ChatManager.js";

const PORT = process.env.PORT || 3000;

let dbManager = new DBManager();
let routingManager = new RoutingManager(dbManager);
let socketManager = new SocketManager(routingManager);  
let sessionManager = new SessionManager(routingManager.app, dbManager);
let authManager = new AuthenticationManager(routingManager.app, sessionManager, dbManager);
let commentManager = new CommentManager(routingManager.app, dbManager, sessionManager);
let userManager = new UserManager(routingManager.app, dbManager, sessionManager, authManager);
let chatManager = new ChatManager(dbManager, sessionManager, socketManager, routingManager.app);

// Gotta load the routes after all the middleware setup
routingManager.initRoutes();

// Start server
socketManager.server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
// Import Managers
import RoutingManager from "./managers/RoutingManager.js";
import AuthenticationManager from "./managers/AuthenticationManager.js";
import SessionManager from "./managers/SessionManager.js";
import DBManager from "./database/DBManager.js";
import CommentManager from "./managers/CommentManager.js";

const PORT = process.env.PORT || 3000;

let dbManager = new DBManager();
let routingManager = new RoutingManager(dbManager);  
let sessionManager = new SessionManager(routingManager.app, dbManager);
let authManager = new AuthenticationManager(routingManager.app, sessionManager, dbManager);
let commentManager = new CommentManager(routingManager.app, dbManager, sessionManager);

routingManager.initRoutes();

// Start server
routingManager.app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
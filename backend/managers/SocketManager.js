// Socket Manager
// Handles WebSocket setup and management

// Imports
import { Server } from "socket.io";
import http from "http";

class SocketManager {
    constructor(app) {
        this.initSocket(app);
    }

    // Initializes shared Express/Socket.io server
    initSocket(app) {
        this.server = http.createServer(app);
        this.io = new Server(this.server, {
            cors: {
                origin: "https://sswd.lax18.dev",
                methods: ["GET", "POST"]
            }
        });
    }
}

export default SocketManager;
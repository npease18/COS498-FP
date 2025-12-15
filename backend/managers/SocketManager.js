import { Server } from "socket.io";
import http from "http";

class SocketManager {
    constructor(rm) {
        this.initSocket(rm.app);
    }

    initSocket(app) {
        this.server = http.createServer(app);
        this.io = new Server(this.server, {
            cors: {
                origin: "*", // TODO: Restrict to Prod
                methods: ["GET", "POST"]
            }
        });
    }
}

export default SocketManager;
// backend/services/agentWebSocket.js
// DISABLED: Remote agents connect via HTTP POST to /api/agent/findings.
// Outbound WebSocket connections to localhost:8000 are not required.
const logger = require('../utils/logger');

class AgentWebSocket {
    constructor() {
        logger.info('ℹ️ Agent WebSocket client DISABLED. Agents push alerts via HTTP.');
        this.enabled = false;
    }

    connect() {
        // No-op
    }

    send() {
        // No-op
    }

    disconnect() {
        // No-op
    }
}

module.exports = new AgentWebSocket();
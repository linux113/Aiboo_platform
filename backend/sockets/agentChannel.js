// backend/sockets/agentChannel.js
//
// Persistent Socket.IO namespace that agents connect to so the backend
// can push remote commands to them.
//
// Namespace:  /agent-channel
// Auth:       x-api-key via handshake (AGENT_API_KEY env var)
// Direction:  Backend → Agent  (commands)
//             Agent  → Backend (register, command-ack)
//
// Reporting of results still flows through the existing REST path
// (POST /api/agent/actions), NOT through this channel. This channel
// only carries the *trigger*; the ActionRecord pipeline stays the
// single source of truth for what happened.

import logger from '../utils/logger.js';

const AGENT_API_KEY =
  process.env.AGENT_API_KEY || 'dev-key-change-in-production';

// ---------------------------------------------------------------------------
// In-memory registries
// ---------------------------------------------------------------------------

// endpoint_id → { socket, endpointId, hostname, lastSeen }
const agents = new Map();

// cmd_id → { cmd_id, endpoint_id, action, target, status, sentAt, completedAt, error }
// Kept small — trimmed to the last 500 entries on every write.
const pendingCommands = new Map();
const MAX_COMMAND_HISTORY = 500;

function trimCommandHistory() {
  if (pendingCommands.size <= MAX_COMMAND_HISTORY) return;
  // Map preserves insertion order — drop oldest first
  const excess = pendingCommands.size - MAX_COMMAND_HISTORY;
  let i = 0;
  for (const key of pendingCommands.keys()) {
    if (i++ >= excess) break;
    pendingCommands.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Public entry point — called once from server bootstrap
// ---------------------------------------------------------------------------
export function registerAgentChannel(io) {
  const nsp = io.of('/agent-channel');

  // ---- Auth middleware ------------------------------------------------
  nsp.use((socket, next) => {
    const { api_key, endpoint_id } = socket.handshake.auth || {};

    if (!api_key || api_key !== AGENT_API_KEY) {
      logger.warn(
        `Agent channel auth FAILED from ${socket.handshake.address} ` +
          `(endpoint_id=${endpoint_id || 'none'})`
      );
      return next(new Error('Invalid API key'));
    }
    if (!endpoint_id) {
      return next(new Error('Missing endpoint_id'));
    }

    socket.endpointId = endpoint_id;
    next();
  });

  // ---- Connection handling -------------------------------------------
  nsp.on('connection', (socket) => {
    const endpointId = socket.endpointId;
    const hostname = socket.handshake.auth?.hostname || endpointId;

    logger.info(`Agent channel connected: ${endpointId} (${hostname})`);

    agents.set(endpointId, {
      socket,
      endpointId,
      hostname,
      lastSeen: new Date().toISOString(),
    });

    // Broadcast updated online list to dashboard clients
    io.emit('agents:online', Array.from(agents.keys()));

    // ---- agent:register -----------------------------------------------
    socket.on('agent:register', (data) => {
      const entry = agents.get(endpointId);
      if (entry) {
        entry.hostname = data?.hostname || entry.hostname;
        entry.lastSeen = new Date().toISOString();
      }
      logger.info(
        `Agent registered: ${endpointId} (${data?.hostname || 'unknown'})`
      );
      io.emit('agents:online', Array.from(agents.keys()));
    });

    // ---- agent:command-ack --------------------------------------------
    // Agent acknowledges receipt or completion of a command
    socket.on('agent:command-ack', (data) => {
      const cmd = pendingCommands.get(data?.cmd_id);
      if (cmd) {
        cmd.status = data.status || cmd.status;
        cmd.completedAt = new Date().toISOString();
        cmd.error = data.error || null;
      }
      io.emit('command:ack', data);
      logger.info(
        `Command ack: ${data?.cmd_id} → ${data?.status}` +
          (data?.error ? ` (${data.error})` : '')
      );
    });

    // ---- disconnect ---------------------------------------------------
    socket.on('disconnect', (reason) => {
      logger.warn(`Agent channel disconnected: ${endpointId} (${reason})`);
      agents.delete(endpointId);
      io.emit('agents:online', Array.from(agents.keys()));
    });
  });

  // ---- API surface used by REST routes --------------------------------
  return {
    /**
     * Push a command to a specific connected agent.
     * Returns { ok: true, cmd_id } on success, or { ok: false, error } if
     * the agent is not currently connected.
     */
    dispatch(endpointId, action, target = '', params = {}) {
      const agent = agents.get(endpointId);
      if (!agent) {
        return {
          ok: false,
          error: `Agent '${endpointId}' is not connected`,
        };
      }

      const cmdId = `cmd_${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 8)}`;

      const command = {
        cmd_id: cmdId,
        action,
        target,
        params,
        sent_at: new Date().toISOString(),
      };

      agent.socket.emit('command', command);

      pendingCommands.set(cmdId, {
        cmd_id: cmdId,
        endpoint_id: endpointId,
        action,
        target,
        status: 'sent',
        sentAt: command.sent_at,
        completedAt: null,
        error: null,
      });
      trimCommandHistory();

      logger.info(`Dispatched ${action} → ${endpointId} (${cmdId})`);
      return { ok: true, cmd_id: cmdId };
    },

    /** List agents currently connected via WebSocket. */
    listAgents() {
      return Array.from(agents.values()).map((a) => ({
        endpointId: a.endpointId,
        hostname: a.hostname,
        lastSeen: a.lastSeen,
      }));
    },

    /** Recent commands (newest first). */
    listCommands() {
      return Array.from(pendingCommands.values()).reverse();
    },

    /** Look up a single command by id. */
    getCommand(cmdId) {
      return pendingCommands.get(cmdId);
    },

    /** Is this endpoint currently connected? */
    isOnline(endpointId) {
      return agents.has(endpointId);
    },
  };
}

export default registerAgentChannel;
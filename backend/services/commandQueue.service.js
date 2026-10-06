// backend/services/commandQueue.service.js
// The REST delivery path for remote commands.
//
// The Windows agent keeps a Socket.IO connection open, so the backend can push a
// command to it directly. A Linux agent cannot (no socket.io in the Python
// standard library) - it POLLS. This module is the queue those agents poll:
//
//   dashboard / approval / playbook
//        -> queueCommand()            (this file)
//        -> GET  /api/agent/commands/pending      (agent picks it up)
//        -> POST /api/agent/commands/:id/ack      (agent reports the result)
//        -> finishCommand()
//
// Keeping it in its own module means both the routes and the response engine can
// use it without importing each other.
import logger from '../utils/logger.js';

const state = {
  commandQueue: [],   // waiting for the endpoint to pick them up
  commandHistory: [], // everything, newest first (queued/sent/executed/failed)
};

export const getCommandState = () => state;

// A command id that is unique and readable in the logs.
export const newCommandId = () => `cmd_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

// Queue a command for an agent that polls over REST. Returns { ok, cmd_id }.
export const queueCommand = (endpoint_id, action, target, params, extra = {}) => {
  if (!endpoint_id || !action) return { ok: false, error: 'endpoint_id and action are required' };
  const cmd_id = newCommandId();
  const entry = {
    cmd_id,
    endpoint_id,
    action,
    target: target || '',
    params: params && typeof params === 'object' ? params : {},
    status: 'queued',
    queued_at: new Date().toISOString(),
    delivered_at: null,
    completed_at: null,
    error: null,
    result: null,
    via: 'rest',
    ...extra,
  };
  state.commandQueue.push(entry);
  if (state.commandQueue.length > 200) state.commandQueue.shift();
  state.commandHistory.unshift(entry);
  if (state.commandHistory.length > 500) state.commandHistory.pop();
  logger.info(`Remote command queued (REST) for ${endpoint_id}: ${action} (${cmd_id})`);
  return { ok: true, cmd_id, queued: true, via: 'rest', entry };
};

// The agent asks for its work and takes the batch away.
export const takePendingCommands = (endpoint_id) => {
  const mine = state.commandQueue.filter((c) => c.endpoint_id === endpoint_id);
  state.commandQueue = state.commandQueue.filter((c) => c.endpoint_id !== endpoint_id);
  const now = new Date().toISOString();
  for (const entry of mine) {
    entry.status = 'sent';
    entry.delivered_at = now;
  }
  return mine;
};

// Remember the outcome of a command (used by the socket path and the REST path).
export const finishCommand = (cmd_id, status, error, result) => {
  const entry = state.commandHistory.find((c) => c.cmd_id === cmd_id);
  if (!entry) return null;
  entry.status = status || entry.status;
  entry.completed_at = new Date().toISOString();
  entry.error = error || null;
  if (result && typeof result === 'object') entry.result = result;
  return entry;
};

// Find one command (either path).
export const findCommand = (cmd_id) => state.commandHistory.find((c) => c.cmd_id === cmd_id) || null;

// Wait for the agent's answer to a queued command (used by approvals/playbooks).
export async function waitForCommand(cmd_id, timeoutMs = 15000, stepMs = 400) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const entry = findCommand(cmd_id);
    if (entry && ['executed', 'failed'].includes(entry.status)) {
      return { ok: entry.status === 'executed', status: entry.status, error: entry.error, result: entry.result, cmd_id };
    }
    if (Date.now() >= deadline) {
      const still = findCommand(cmd_id);
      return {
        ok: false, status: 'timeout', cmd_id,
        error: `No answer from the agent in ${Math.round(timeoutMs / 1000)} s`
              + (still ? ` (command is ${still.status})` : ''),
        result: still?.result || null,
      };
    }
    // NOTE: kept ref'd on purpose - while we wait, the event loop must stay alive
    // so the timer really fires (unref'd timers let a small process exit early).
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

// src/services/response.service.js
import ResponseAction from '../models/ResponseAction.js';
import Threat from '../models/Threat.js';
import { getIO } from '../config/socket.js';

/**
 * Emit a socket event for any response action
 * @param {Object} action - The ResponseAction document
 * @returns {Object} The same action
 */
const emitResponse = (action) => {
  const io = getIO();
  io.emit('response:triggered', action);
  return action;
};

/**
 * Isolate a device (IP)
 */
export const isolateDevice = async (ip, userId) => {
  const action = await ResponseAction.create({
    type: 'isolate',
    target: ip,
    triggeredBy: userId,
  });
  return emitResponse(action);
};

/**
 * Block an IP
 */
export const blockIP = async (ip, userId) => {
  const action = await ResponseAction.create({
    type: 'block',
    target: ip,
    triggeredBy: userId,
  });
  return emitResponse(action);
};

/**
 * Lock a zone
 */
export const lockZone = async (zone, userId) => {
  const action = await ResponseAction.create({
    type: 'lock',
    target: zone,
    triggeredBy: userId,
  });
  return emitResponse(action);
};

/**
 * Escalate an incident (threat)
 */
export const elevateIncident = async (threatId, userId) => {
  const action = await ResponseAction.create({
    type: 'escalate',
    target: threatId,
    triggeredBy: userId,
  });
  return emitResponse(action);
};

/**
 * Auto‑respond to a threat
 * Works with both MongoDB ObjectId (Threat model) and string IDs (in-memory findings)
 */
export const autoRespond = async (threatId, userId) => {
  let threat = null;
  try {
    threat = await Threat.findById(threatId);
  } catch {
    // not a valid ObjectId — use in-memory fallback
  }
  if (!threat) {
    try {
      threat = await Threat.findOne({ id: threatId });
    } catch {
      // ignore
    }
  }
  // if still not found, proceed anyway (for in-memory demo findings)
  if (threat) {
    threat.status = 'investigating';
    await threat.save();
  }

  const action = await ResponseAction.create({
    type: 'auto',
    target: threatId,
    triggeredBy: userId,
  });
  return emitResponse(action);
};
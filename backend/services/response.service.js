// src/services/response.service.js
import ResponseAction from '../models/ResponseAction.js';
import Threat from '../models/Threat.js';
import { getIO } from '../config/socket.js';

/**
 * Emit a socket event for any response action
 * @param {Object} action - The ResponseAction document
 * @returns {Object} The same action
 */
const emitResponse = (action, organizationId) => {
  if (organizationId) {
    try { getIO().to(`org:${organizationId}`).emit('response:triggered', action); } catch {}
  }
  return action;
};

/**
 * Isolate a device (IP)
 */
export const isolateDevice = async (ip, userId, organizationId) => {
  const action = await ResponseAction.create({
    type: 'isolate',
    target: ip,
    triggeredBy: userId,
    ...(organizationId ? { organization: organizationId } : {}),
  });
  return emitResponse(action, organizationId);
};

/**
 * Block an IP
 */
export const blockIP = async (ip, userId, organizationId) => {
  const action = await ResponseAction.create({
    type: 'block',
    target: ip,
    triggeredBy: userId,
    ...(organizationId ? { organization: organizationId } : {}),
  });
  return emitResponse(action, organizationId);
};

/**
 * Lock a zone
 */
export const lockZone = async (zone, userId, organizationId) => {
  const action = await ResponseAction.create({
    type: 'lock',
    target: zone,
    triggeredBy: userId,
    ...(organizationId ? { organization: organizationId } : {}),
  });
  return emitResponse(action, organizationId);
};

/**
 * Escalate an incident (threat)
 */
export const elevateIncident = async (threatId, userId, organizationId) => {
  const action = await ResponseAction.create({
    type: 'escalate',
    target: threatId,
    triggeredBy: userId,
    ...(organizationId ? { organization: organizationId } : {}),
  });
  return emitResponse(action, organizationId);
};

/**
 * Auto‑respond to a threat
 * Works with both MongoDB ObjectId (Threat model) and string IDs (in-memory findings)
 */
export const autoRespond = async (threatId, userId, organizationId) => {
  let threat = null;
  try {
    threat = await Threat.findOne({ _id: threatId, ...(organizationId ? { organization: organizationId } : {}) });
  } catch {
    // not a valid ObjectId — use in-memory fallback
  }
  if (!threat) {
    try {
      threat = await Threat.findOne({ id: threatId, ...(organizationId ? { organization: organizationId } : {}) });
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
    ...(organizationId ? { organization: organizationId } : {}),
  });
  return emitResponse(action, organizationId);
};
import Camera from '../models/Camera.js';
import Detection from '../models/Detection.js';
import { getIO } from '../config/socket.js';

const emit = (event, data) => { try { getIO().emit(event, data); } catch {} };

export const listCameras = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const [data, total] = await Promise.all([
    Camera.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit),
    Camera.countDocuments(filter),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const getCameraById = async (id) => {
  const cam = await Camera.findById(id);
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  return cam;
};

export const addCamera = async (data, userId) => {
  const cam = await Camera.create({ ...data, addedBy: userId });
  emit('camera:added', cam);
  return cam;
};

export const updateCamera = async (id, data) => {
  const cam = await Camera.findByIdAndUpdate(id, data, { new: true });
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  emit('camera:updated', cam);
  return cam;
};

export const deleteCamera = async (id) => {
  const cam = await Camera.findByIdAndDelete(id);
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  emit('camera:deleted', { id });
  return { success: true };
};

export const listDetections = async (filter = {}, limit = 100) =>
  Detection.find(filter).sort({ timestamp: -1 }).limit(limit);

export const createDetection = async (data) => {
  const detection = await Detection.create(data);
  emit('detection:new', detection);
  if (['weapon_gun', 'weapon_knife', 'face_watchlist'].includes(data.type)) {
    emit('alert:critical', {
      type: data.type, cameraId: data.cameraId,
      cameraName: data.cameraName, location: data.location,
      confidence: data.confidence, timestamp: detection.timestamp,
      message: buildAlertMessage(data),
    });
  }
  return detection;
};

export const acknowledgeDetection = async (id) => {
  const det = await Detection.findByIdAndUpdate(id, { acknowledged: true }, { new: true });
  if (!det) throw { statusCode: 404, message: 'Detection not found' };
  return det;
};

export const escalateDetection = async (id) => {
  const det = await Detection.findByIdAndUpdate(id, { escalated: true, severity: 'critical' }, { new: true });
  if (!det) throw { statusCode: 404, message: 'Detection not found' };
  emit('alert:escalated', det);
  return det;
};

export const runDetection = async (cameraId) => {
  const cam = await getCameraById(cameraId);
  if (!cam?.enabled) return null;
  const types = ['person', 'vehicle', 'behavior_anomaly', 'crowd', 'bag'];
  const critTypes = ['weapon_gun', 'weapon_knife', 'face_watchlist', 'face_unknown'];
  const pool = Math.random() > 0.85 ? critTypes : types;
  const type = pool[Math.floor(Math.random() * pool.length)];
  const severity = ['weapon_gun', 'weapon_knife', 'face_watchlist'].includes(type) ? 'critical'
    : ['face_unknown', 'behavior_anomaly'].includes(type) ? 'high'
    : type === 'crowd' ? 'medium' : 'low';
  return createDetection({
    cameraId: cam._id, cameraName: cam.name, location: cam.location,
    type, severity, confidence: Math.floor(70 + Math.random() * 30),
    label: buildLabel(type), metadata: { zone: cam.zone },
  });
};

function buildLabel(type) {
  const m = {
    person: 'Person Detected', vehicle: 'Vehicle Detected',
    weapon_gun: 'GUN DETECTED', weapon_knife: 'KNIFE DETECTED',
    face_known: 'Known Person', face_unknown: 'Unknown Person',
    face_watchlist: 'WATCHLIST MATCH', crowd: 'High Crowd Density',
    behavior_anomaly: 'Suspicious Behavior', bag: 'Unattended Bag', breach: 'Zone Breach',
  };
  return m[type] || type;
}

function buildAlertMessage(data) {
  const loc = data.location || data.cameraName;
  if (data.type === 'weapon_gun') return `Gun detected at ${loc}`;
  if (data.type === 'weapon_knife') return `Knife detected at ${loc}`;
  if (data.type === 'face_watchlist') return `Watchlist subject spotted at ${loc}`;
  return `Critical alert at ${loc}`;
}

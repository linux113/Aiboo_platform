import Camera from '../models/Camera.js';
import Detection from '../models/Detection.js';
import { getIO } from '../config/socket.js';

const tenantFilter = (filter = {}, organizationId) => organizationId
  ? { ...filter, organization: organizationId }
  : filter;
const emit = (event, data, organizationId) => {
  if (!organizationId) return;
  try { getIO().to(`org:${organizationId}`).emit(event, data); } catch {}
};

export const listCameras = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const query = tenantFilter(filter, options.organizationId);
  const [data, total] = await Promise.all([
    Camera.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
    Camera.countDocuments(query),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const getCameraById = async (id, organizationId) => {
  const cam = await Camera.findOne({ _id: id, ...(organizationId ? { organization: organizationId } : {}) });
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  return cam;
};

export const addCamera = async (data, userId, organizationId) => {
  const cam = await Camera.create({ ...data, addedBy: userId, ...(organizationId ? { organization: organizationId } : {}) });
  emit('camera:added', cam, organizationId);
  return cam;
};

export const updateCamera = async (id, data, organizationId) => {
  const cam = await Camera.findOneAndUpdate(
    { _id: id, ...(organizationId ? { organization: organizationId } : {}) },
    { ...data, ...(organizationId ? { organization: organizationId } : {}) },
    { new: true },
  );
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  emit('camera:updated', cam, organizationId);
  return cam;
};

export const deleteCamera = async (id, organizationId) => {
  const cam = await Camera.findOneAndDelete({ _id: id, ...(organizationId ? { organization: organizationId } : {}) });
  if (!cam) throw { statusCode: 404, message: 'Camera not found' };
  emit('camera:deleted', { id }, organizationId);
  return { success: true };
};

export const listDetections = async (filter = {}, limit = 100, organizationId) =>
  Detection.find(tenantFilter(filter, organizationId)).sort({ timestamp: -1 }).limit(limit);

export const createDetection = async (data, organizationId) => {
  if (organizationId && data.cameraId) {
    const camera = await Camera.findOne({ _id: data.cameraId, organization: organizationId }).select('_id');
    if (!camera) throw { statusCode: 404, message: 'Camera not found in this company workspace' };
  }
  const detection = await Detection.create({ ...data, ...(organizationId ? { organization: organizationId } : {}) });
  emit('detection:new', detection, organizationId);
  if (['weapon_gun', 'weapon_knife', 'face_watchlist'].includes(data.type)) {
    emit('alert:critical', {
      type: data.type, cameraId: data.cameraId,
      cameraName: data.cameraName, location: data.location,
      confidence: data.confidence, timestamp: detection.timestamp,
      message: buildAlertMessage(data),
    }, organizationId);
  }
  return detection;
};

export const acknowledgeDetection = async (id, organizationId) => {
  const det = await Detection.findOneAndUpdate(
    { _id: id, ...(organizationId ? { organization: organizationId } : {}) },
    { acknowledged: true }, { new: true },
  );
  if (!det) throw { statusCode: 404, message: 'Detection not found' };
  return det;
};

export const escalateDetection = async (id, organizationId) => {
  const det = await Detection.findOneAndUpdate(
    { _id: id, ...(organizationId ? { organization: organizationId } : {}) },
    { escalated: true, severity: 'critical' }, { new: true },
  );
  if (!det) throw { statusCode: 404, message: 'Detection not found' };
  emit('alert:escalated', det, organizationId);
  return det;
};

export const runDetection = async (cameraId, organizationId) => {
  const cam = await getCameraById(cameraId, organizationId);
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
  }, organizationId);
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

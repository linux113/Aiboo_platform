import Threat from '../models/Threat.js';
import { getIO } from '../config/socket.js';

const emit = (event, data) => { try { getIO().emit(event, data); } catch {} };

export const listThreats = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const [data, total] = await Promise.all([
    Threat.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit),
    Threat.countDocuments(filter),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const createThreat = async (data) => {
  const threat = await Threat.create(data);
  emit('threat:new', threat);
  return threat;
};

export const updateThreat = async (id, data) => {
  const threat = await Threat.findByIdAndUpdate(id, data, { new: true });
  if (!threat) throw { statusCode: 404, message: 'Threat not found' };
  emit('threat:update', threat);
  return threat;
};

export const getThreatById = async (id) => {
  const threat = await Threat.findById(id);
  if (!threat) throw { statusCode: 404, message: 'Threat not found' };
  return threat;
};

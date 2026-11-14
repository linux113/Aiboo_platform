import Threat from '../models/Threat.js';
import { getIO } from '../config/socket.js';

const tenantFilter = (filter = {}, organizationId) => organizationId
  ? { ...filter, organization: organizationId }
  : filter;
const emit = (event, data, organizationId) => {
  if (!organizationId) return; // never broadcast tenant-owned data without a tenant context
  try { getIO().to(`org:${organizationId}`).emit(event, data); } catch {}
};

export const listThreats = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const query = tenantFilter(filter, options.organizationId);
  const [data, total] = await Promise.all([
    Threat.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit),
    Threat.countDocuments(query),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const createThreat = async (data, organizationId) => {
  const threat = await Threat.create({ ...data, ...(organizationId ? { organization: organizationId } : {}) });
  emit('threat:new', threat, organizationId);
  return threat;
};

export const updateThreat = async (id, data, organizationId) => {
  const filter = { _id: id, ...(organizationId ? { organization: organizationId } : {}) };
  const threat = await Threat.findOneAndUpdate(filter, {
    ...data,
    ...(organizationId ? { organization: organizationId } : {}),
  }, { new: true });
  if (!threat) throw { statusCode: 404, message: 'Threat not found' };
  emit('threat:update', threat, organizationId);
  return threat;
};

export const getThreatById = async (id, organizationId) => {
  const filter = { _id: id, ...(organizationId ? { organization: organizationId } : {}) };
  const threat = await Threat.findOne(filter);
  if (!threat) throw { statusCode: 404, message: 'Threat not found' };
  return threat;
};

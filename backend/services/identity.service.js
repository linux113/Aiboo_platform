import IdentityRisk from '../models/IdentityRisk.js';
import { getIO } from '../config/socket.js';

const tenantFilter = (filter = {}, organizationId) => organizationId
  ? { ...filter, organization: organizationId }
  : filter;

export const listIdentities = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const query = tenantFilter(filter, options.organizationId);
  const [data, total] = await Promise.all([
    IdentityRisk.find(query).populate('userId').sort({ createdAt: -1 }).skip(skip).limit(limit),
    IdentityRisk.countDocuments(query),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const getIdentity = async (id, organizationId) => {
  const identity = await IdentityRisk.findOne({ _id: id, ...(organizationId ? { organization: organizationId } : {}) }).populate('userId');
  if (!identity) throw { statusCode: 404, message: 'Identity not found' };
  return identity;
};

export const updateIdentity = async (id, data, organizationId) => {
  const identity = await IdentityRisk.findOneAndUpdate(
    { _id: id, ...(organizationId ? { organization: organizationId } : {}) },
    { ...data, ...(organizationId ? { organization: organizationId } : {}) }, { new: true },
  );
  if (!identity) throw { statusCode: 404, message: 'Identity not found' };
  if (data.flagged && organizationId) {
    try { getIO().to(`org:${organizationId}`).emit('identity:flagged', identity); } catch {}
  }
  return identity;
};

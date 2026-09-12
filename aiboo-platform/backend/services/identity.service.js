import IdentityRisk from '../models/IdentityRisk.js';
import { getIO } from '../config/socket.js';

export const listIdentities = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const [data, total] = await Promise.all([
    IdentityRisk.find(filter).populate('userId').sort({ createdAt: -1 }).skip(skip).limit(limit),
    IdentityRisk.countDocuments(filter),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const getIdentity = async (id) => {
  const identity = await IdentityRisk.findById(id).populate('userId');
  if (!identity) throw { statusCode: 404, message: 'Identity not found' };
  return identity;
};

export const updateIdentity = async (id, data) => {
  const identity = await IdentityRisk.findByIdAndUpdate(id, data, { new: true });
  if (!identity) throw { statusCode: 404, message: 'Identity not found' };
  if (data.flagged) {
    const io = getIO();
    io.emit('identity:flagged', identity);
  }
  return identity;
};

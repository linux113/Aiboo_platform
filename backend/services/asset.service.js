import Asset from '../models/Asset.js';
import Vulnerability from '../models/Vulnerability.js';
import { getIO } from '../config/socket.js';

const tenantFilter = (filter = {}, organizationId) => organizationId
  ? { ...filter, organization: organizationId }
  : filter;

export const listAssets = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const query = tenantFilter(filter, options.organizationId);
  const [data, total] = await Promise.all([
    Asset.find(query).populate('vulnerabilities').sort({ createdAt: -1 }).skip(skip).limit(limit),
    Asset.countDocuments(query),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const createAsset = async (data, organizationId) =>
  Asset.create({ ...data, ...(organizationId ? { organization: organizationId } : {}) });

export const runScan = async (assetId, organizationId) => {
  const filter = { _id: assetId, ...(organizationId ? { organization: organizationId } : {}) };
  const asset = await Asset.findOne(filter);
  if (!asset) throw { statusCode: 404, message: 'Asset not found' };

  const vuln = await Vulnerability.create({
    cve: `CVE-2024-XXXX-${Math.floor(Math.random() * 1000)}`,
    severity: 'high',
    cvss: 7.5,
    assetId: asset._id,
    ...(organizationId ? { organization: organizationId } : {}),
  });
  asset.vulnerabilities.push(vuln);
  asset.lastScan = new Date();
  await asset.save();

  if (organizationId) {
    try { getIO().to(`org:${organizationId}`).emit('scan:completed', { assetId: asset._id, vulnerability: vuln }); } catch {}
  }
  return vuln;
};

export const listVulnerabilities = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const query = tenantFilter(filter, options.organizationId);
  const [data, total] = await Promise.all([
    Vulnerability.find(query).populate('assetId').sort({ createdAt: -1 }).skip(skip).limit(limit),
    Vulnerability.countDocuments(query),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

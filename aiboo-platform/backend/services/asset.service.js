import Asset from '../models/Asset.js';
import Vulnerability from '../models/Vulnerability.js';
import { getIO } from '../config/socket.js';

export const listAssets = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const [data, total] = await Promise.all([
    Asset.find(filter).populate('vulnerabilities').sort({ createdAt: -1 }).skip(skip).limit(limit),
    Asset.countDocuments(filter),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

export const createAsset = async (data) => Asset.create(data);

export const runScan = async (assetId) => {
  const asset = await Asset.findById(assetId);
  if (!asset) throw { statusCode: 404, message: 'Asset not found' };

  const vuln = await Vulnerability.create({
    cve: `CVE-2024-XXXX-${Math.floor(Math.random() * 1000)}`,
    severity: 'high',
    cvss: 7.5,
    assetId: asset._id,
  });
  asset.vulnerabilities.push(vuln);
  asset.lastScan = new Date();
  await asset.save();

  const io = getIO();
  io.emit('scan:completed', { assetId: asset._id, vulnerability: vuln });
  return vuln;
};

export const listVulnerabilities = async (filter = {}, options = {}) => {
  const page = options.page || 1;
  const limit = options.limit || 20;
  const skip = (page - 1) * limit;
  const [data, total] = await Promise.all([
    Vulnerability.find(filter).populate('assetId').sort({ createdAt: -1 }).skip(skip).limit(limit),
    Vulnerability.countDocuments(filter),
  ]);
  return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
};

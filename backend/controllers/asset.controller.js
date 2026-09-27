import { listAssets, createAsset, runScan, listVulnerabilities } from '../services/asset.service.js';

export const getAssets = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const assets = await listAssets({}, { page, limit });
    res.json(assets);
  } catch (err) { next(err); }
};

export const postAsset = async (req, res, next) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Asset name is required' });
    const asset = await createAsset(req.body);
    res.status(201).json(asset);
  } catch (err) { next(err); }
};

export const runAssetScan = async (req, res, next) => {
  try {
    if (!req.params.assetId) return res.status(400).json({ message: 'Asset ID is required' });
    const vuln = await runScan(req.params.assetId);
    res.status(201).json(vuln);
  } catch (err) { next(err); }
};

export const getVulnerabilities = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const vulns = await listVulnerabilities({}, { page, limit });
    res.json(vulns);
  } catch (err) { next(err); }
};

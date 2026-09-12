import { listThreats, createThreat, updateThreat, getThreatById } from '../services/threat.service.js';

export const getThreats = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const allowedFilters = ['severity', 'status', 'source', 'asset', 'title'];
    const filter = {};
    for (const key of allowedFilters) {
      if (req.query[key]) filter[key] = req.query[key];
    }
    const result = await listThreats(filter, { page, limit });
    res.json(result);
  } catch (err) { next(err); }
};

export const postThreat = async (req, res, next) => {
  try {
    const { severity, title, source } = req.body;
    if (!severity || !title || !source) {
      return res.status(400).json({ message: 'severity, title, and source are required' });
    }
    const threat = await createThreat(req.body);
    res.status(201).json(threat);
  } catch (err) { next(err); }
};

export const patchThreat = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Threat ID is required' });
    const threat = await updateThreat(req.params.id, req.body);
    res.json(threat);
  } catch (err) { next(err); }
};

export const getThreat = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Threat ID is required' });
    const threat = await getThreatById(req.params.id);
    res.json(threat);
  } catch (err) { next(err); }
};

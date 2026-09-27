import ResponseAction from '../models/ResponseAction.js';
import {
  isolateDevice,
  blockIP,
  lockZone,
  elevateIncident,
  autoRespond,
} from '../services/response.service.js';

export const isolateCtrl = async (req, res, next) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ message: 'IP is required' });
    const action = await isolateDevice(ip, req.user.id);
    res.status(201).json(action);
  } catch (err) { next(err); }
};

export const blockCtrl = async (req, res, next) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ message: 'IP is required' });
    const action = await blockIP(ip, req.user.id);
    res.status(201).json(action);
  } catch (err) { next(err); }
};

export const lockCtrl = async (req, res, next) => {
  try {
    const { zone } = req.body;
    if (!zone) return res.status(400).json({ message: 'Zone is required' });
    const action = await lockZone(zone, req.user.id);
    res.status(201).json(action);
  } catch (err) { next(err); }
};

export const elevateCtrl = async (req, res, next) => {
  try {
    const { threatId } = req.body;
    if (!threatId) return res.status(400).json({ message: 'threatId is required' });
    const action = await elevateIncident(threatId, req.user.id);
    res.status(201).json(action);
  } catch (err) { next(err); }
};

export const autoRespondCtrl = async (req, res, next) => {
  try {
    const { threatId } = req.body;
    if (!threatId) return res.status(400).json({ message: 'threatId is required' });
    const action = await autoRespond(threatId, req.user.id);
    res.status(201).json(action);
  } catch (err) { next(err); }
};

export const responseLogCtrl = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      ResponseAction.find().sort({ timestamp: -1 }).skip(skip).limit(limit),
      ResponseAction.countDocuments(),
    ]);
    res.json({ data, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
};

import { listIdentities, getIdentity, updateIdentity } from '../services/identity.service.js';

export const getIdentities = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const ids = await listIdentities({}, { page, limit });
    res.json(ids);
  } catch (err) { next(err); }
};

export const getIdentityById = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Identity ID is required' });
    const id = await getIdentity(req.params.id);
    res.json(id);
  } catch (err) { next(err); }
};

export const patchIdentity = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Identity ID is required' });
    const id = await updateIdentity(req.params.id, req.body);
    res.json(id);
  } catch (err) { next(err); }
};

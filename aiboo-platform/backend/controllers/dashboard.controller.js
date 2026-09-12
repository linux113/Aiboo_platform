import { getKPIs } from '../services/kpi.service.js';

export const getKPIsCtrl = async (req, res, next) => {
  try {
    const kpis = await getKPIs();
    res.json(kpis);
  } catch (err) { next(err); }
};

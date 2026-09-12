import { analyzeThreats, explainAlert, chatWithAI } from '../services/ai.service.js';

export const analyzeCtrl = async (req, res, next) => {
  try {
    const result = await analyzeThreats();
    res.json(result);
  } catch (e) { next(e); }
};

export const explainCtrl = async (req, res, next) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ message: 'query is required' });
    res.json(await explainAlert(query));
  } catch (e) { next(e); }
};

export const chatCtrl = async (req, res, next) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'message is required' });
    res.json(await chatWithAI(message, req.body.history || []));
  } catch (e) { next(e); }
};

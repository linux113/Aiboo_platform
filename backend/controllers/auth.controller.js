import { register, login, getMe, changePassword } from '../services/auth.service.js';
import logger from '../utils/logger.js';

export const registerCtrl = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }
    const { token, user } = await register(req.body, req.user);
    res.status(201).json({ token, user });
  } catch (err) { next(err); }
};

export const loginCtrl = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const { token, user, mustChangePassword } = await login(req.body);
    if (mustChangePassword) {
      logger.warn(`SECURITY: ${user.email} logged in with a default password - it must be changed`);
    }
    res.json({ token, user, mustChangePassword });
  } catch (err) { next(err); }
};

export const meCtrl = async (req, res, next) => {
  try {
    const user = await getMe(req.user.id);
    res.json(user);
  } catch (err) { next(err); }
};

export const changePasswordCtrl = async (req, res, next) => {
  try {
    await changePassword(req.user.id, req.body || {});
    logger.info(`Password changed for user ${req.user.email || req.user.id}`);
    res.json({ ok: true, message: 'Password changed' });
  } catch (err) { next(err); }
};

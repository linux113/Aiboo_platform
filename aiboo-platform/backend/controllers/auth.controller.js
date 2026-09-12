import { register, login, getMe } from '../services/auth.service.js';

export const registerCtrl = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }
    const { token, user } = await register(req.body);
    res.status(201).json({ token, user });
  } catch (err) { next(err); }
};

export const loginCtrl = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const { token, user } = await login(req.body);
    res.json({ token, user });
  } catch (err) { next(err); }
};

export const meCtrl = async (req, res, next) => {
  try {
    const user = await getMe(req.user.id);
    res.json(user);
  } catch (err) { next(err); }
};

import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import { isDefaultPassword, validateNewPassword } from '../utils/passwords.js';

const signToken = (user) =>
  jwt.sign(
    { id: user._id, role: user.role, email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

export const register = async ({ name, email, password, role }) => {
  const existing = await User.findOne({ email });
  if (existing) throw { statusCode: 400, message: 'Registration failed' };
  const user = await User.create({ name, email, password, role: role || 'analyst' });
  const token = signToken(user);
  return { token, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
};

export const login = async ({ email, password }) => {
  const user = await User.findOne({ email });
  if (!user) throw { statusCode: 401, message: 'Invalid credentials' };
  const isMatch = await user.matchPassword(password);
  if (!isMatch) throw { statusCode: 401, message: 'Invalid credentials' };
  await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });
  const token = signToken(user);
  // Tell the dashboard to nag the user until a shipped default is replaced.
  const mustChangePassword = isDefaultPassword(password);
  return {
    token,
    mustChangePassword,
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  };
};

export const changePassword = async (userId, { currentPassword, newPassword }) => {
  if (!currentPassword || !newPassword) {
    throw { statusCode: 400, message: 'Current and new password are required' };
  }
  const user = await User.findById(userId);
  if (!user) throw { statusCode: 404, message: 'User not found' };
  if (!(await user.matchPassword(currentPassword))) {
    throw { statusCode: 401, message: 'Current password is wrong' };
  }
  if (currentPassword === newPassword) {
    throw { statusCode: 400, message: 'New password must be different from the current one' };
  }
  const problem = validateNewPassword(newPassword);
  if (problem) throw { statusCode: 400, message: problem };
  user.password = newPassword; // hashed by the pre-save hook
  await user.save();
  return { ok: true };
};

export const getMe = async (userId) => {
  const user = await User.findById(userId).select('-password');
  if (!user) throw { statusCode: 404, message: 'User not found' };
  return user;
};

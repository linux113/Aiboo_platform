import User from '../models/User.js';
import jwt from 'jsonwebtoken';

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
  return { token, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
};

export const getMe = async (userId) => {
  const user = await User.findById(userId).select('-password');
  if (!user) throw { statusCode: 404, message: 'User not found' };
  return user;
};

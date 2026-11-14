import User from '../models/User.js';
import Organization from '../models/Organization.js';
import Subscription from '../models/Subscription.js';
import Plan from '../models/Plan.js';
import jwt from 'jsonwebtoken';
import { forgetUser } from '../middleware/auth.js';
import { isDefaultPassword, validateNewPassword } from '../utils/passwords.js';

export const ROLES = ['admin', 'analyst', 'viewer'];

const signToken = (user) =>
  jwt.sign(
    { id: user._id, role: user.role, email: user.email, name: user.name, organization: user.organization ? String(user.organization) : null },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

const publicUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  organization: user.organization ? String(user.organization) : null,
  active: user.active !== false,
  lastLogin: user.lastLogin || null,
  createdAt: user.createdAt || null,
});

const checkRole = (role) => {
  if (!ROLES.includes(String(role || '').toLowerCase())) {
    throw { statusCode: 400, message: `Role must be one of: ${ROLES.join(', ')}` };
  }
  return String(role).toLowerCase();
};

const cleanEmail = (email) => String(email || '').trim().toLowerCase();

const ensureUserSeatAvailable = async (organizationId, excludeUserId = null) => {
  if (!organizationId) return;
  const organization = await Organization.findById(organizationId).select('isLegacy');
  if (!organization) throw { statusCode: 403, message: 'Company workspace not found' };
  if (organization.isLegacy) return;
  const now = new Date();
  const subscription = await Subscription.findOne({
    organization: organizationId,
    status: 'active',
    currentPeriodStart: { $lte: now },
    currentPeriodEnd: { $gt: now },
  }).sort({ currentPeriodEnd: -1 });
  if (!subscription) throw { statusCode: 402, message: 'An active subscription is required to add users' };
  const plan = await Plan.findById(subscription.plan).select('limits enabled');
  if (!plan || plan.enabled === false) throw { statusCode: 402, message: 'The company subscription plan is unavailable' };
  if (plan.limits?.users == null) return;
  const limit = Number(plan.limits.users);
  if (!Number.isFinite(limit)) return;
  const query = { organization: organizationId, active: { $ne: false }, ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}) };
  const seats = await User.countDocuments(query);
  if (seats >= limit) throw { statusCode: 409, message: `User limit reached for this subscription plan (${limit} seats)` };
};

// A user is created by an admin (dashboard -> Settings -> Users, or
// `npm run add-user`). There is no public self-registration: before, anyone who
// reached the login page could create their own admin account.
export const register = async ({ name, email, password, role }, actor = null) => {
  const mail = cleanEmail(email);
  if (!name || !mail || !password) {
    throw { statusCode: 400, message: 'Name, email and password are required' };
  }
  const problem = validateNewPassword(password);
  if (problem) throw { statusCode: 400, message: problem };
  const wanted = checkRole(role || 'viewer');
  if (actor && actor.role !== 'admin') {
    throw { statusCode: 403, message: 'Only an admin can create users' };
  }
  const existing = await User.findOne({ email: mail });
  if (existing) throw { statusCode: 400, message: 'That email already has an account' };
  if (actor?.organization) await ensureUserSeatAvailable(actor.organization);
  const user = await User.create({
    name: String(name).trim(), email: mail, password, role: wanted,
    organization: actor?.organization || null,
  });
  const token = signToken(user);
  return { token, user: publicUser(user) };
};

export const login = async ({ email, password }) => {
  const mail = cleanEmail(email);
  const user = await User.findOne({ email: mail }) || await User.findOne({ email });
  if (!user) throw { statusCode: 401, message: 'Invalid credentials' };
  if (user.active === false) {
    throw { statusCode: 403, message: 'This account has been disabled by an admin' };
  }
  const isMatch = await user.matchPassword(password);
  if (!isMatch) throw { statusCode: 401, message: 'Invalid credentials' };
  await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });
  const token = signToken(user);
  // Tell the dashboard to nag the user until a shipped default is replaced.
  const mustChangePassword = isDefaultPassword(password);
  return { token, mustChangePassword, user: publicUser(user) };
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
  return {
    id: user._id, name: user.name, email: user.email, role: user.role,
    organization: user.organization ? String(user.organization) : null,
    active: user.active !== false, lastLogin: user.lastLogin || null,
  };
};

// ---------------------------------------------------------------- user admin
// Everything below is admin-only (enforced again by the route).

export const listUsers = async (organizationId = null) => {
  const filter = organizationId ? { organization: organizationId } : {};
  const users = await User.find(filter).select('-password').sort({ createdAt: 1 });
  return users.map(publicUser);
};

const activeAdmins = async (excludeId = null, organizationId = null) => {
  const filter = { role: 'admin' };
  if (organizationId) filter.organization = organizationId;
  const admins = await User.find(filter);
  return admins.filter((u) => u.active !== false && String(u._id) !== String(excludeId || ''));
};

export const updateUser = async (id, patch = {}, actor = null) => {
  const filter = { _id: id };
  if (actor?.organization) filter.organization = actor.organization;
  const user = await User.findOne(filter);
  if (!user) throw { statusCode: 404, message: 'User not found' };
  const self = actor && String(actor.id || '') === String(user._id);
  const organizationId = actor?.organization || null;

  if (patch.role !== undefined) {
    const wanted = checkRole(patch.role);
    if (self) throw { statusCode: 400, message: 'You cannot change your own role' };
    if (user.role === 'admin' && wanted !== 'admin' && (await activeAdmins(user._id, organizationId)).length === 0) {
      throw { statusCode: 400, message: 'This is the last admin - make someone else an admin first' };
    }
    user.role = wanted;
  }

  if (patch.active !== undefined) {
    const on = Boolean(patch.active);
    if (self && !on) throw { statusCode: 400, message: 'You cannot disable your own account' };
    if (on && user.active === false) await ensureUserSeatAvailable(organizationId, user._id);
    if (!on && user.role === 'admin' && (await activeAdmins(user._id, organizationId)).length === 0) {
      throw { statusCode: 400, message: 'This is the last admin - create another admin first' };
    }
    user.active = on;
  }

  if (patch.password) {
    const problem = validateNewPassword(patch.password);
    if (problem) throw { statusCode: 400, message: problem };
    user.password = patch.password; // hashed by the pre-save hook
  }

  if (patch.name) user.name = String(patch.name).trim().slice(0, 120);

  await user.save();
  forgetUser(user._id);   // role / disabled changes apply at once, not after the token expires
  return publicUser(user);
};

// Deleting is deliberately soft: the account is disabled so that anything it
// did (approvals, actions, audit lines) keeps pointing at a real person.
export const disableUser = async (id, actor = null) => updateUser(id, { active: false }, actor);

export const ensureRoleNames = () => ROLES;

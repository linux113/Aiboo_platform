import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import User from '../models/User.js';

const tokenBlacklist = new Map();
const BLACKLIST_TTL = 24 * 60 * 60 * 1000;

const isBlacklisted = (token) => {
  const added = tokenBlacklist.get(token);
  if (!added) return false;
  if (Date.now() - added > BLACKLIST_TTL) {
    tokenBlacklist.delete(token);
    return false;
  }
  return true;
};

export const addToBlacklist = (token) => {
  tokenBlacklist.set(token, Date.now());
};

// A JWT lives for 7 days, so without this an admin could disable an account or
// lower its role and the old token would keep working until it expired. We
// re-read the user (cached for a few seconds) and use the CURRENT role.
const userCache = new Map();          // id -> { role, active, at }
const CACHE_MS = 15000;
// Without a database (unit tests, or a stopped MongoDB) there is nothing to
// re-read, and a buffered query would just stall every request.
const dbConnected = () => mongoose.connection?.readyState === 1;
export const forgetUser = (id) => userCache.delete(String(id));

const freshUser = async (id) => {
  const key = String(id);
  const hit = userCache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit;
  const u = await User.findById(id).select('role active');
  const fresh = { role: u?.role || null, active: u ? u.active !== false : false, at: Date.now() };
  userCache.set(key, fresh);
  return fresh;
};

export const protect = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (isBlacklisted(token)) {
      return res.status(401).json({ message: 'Token revoked' });
    }
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
    req.user = decoded;
    // Best effort: if the database is unreachable we keep the token's claims
    // (the dashboard stays usable), otherwise the stored user wins.
    try {
      if (decoded.id && dbConnected()) {
        const fresh = await freshUser(decoded.id);
        if (fresh.active === false) {
          return res.status(403).json({ message: 'This account has been disabled by an admin' });
        }
        if (fresh.role) req.user = { ...decoded, role: fresh.role };
      }
    } catch {
      /* keep the token claims */
    }
    return next();
  }

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const keysStr = process.env.API_KEYS || '';
    const validKeys = keysStr ? keysStr.split(',').map(k => k.trim()) : [];
    if (validKeys.length === 0) {
      return res.status(401).json({ message: 'API key authentication not configured' });
    }
    if (validKeys.includes(apiKey)) {
      req.user = { id: null, role: 'service', email: 'service@aiboo' };
      return next();
    }
  }

  return res.status(401).json({ message: 'Not authorized, token missing' });
};

export const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden: insufficient role' });
  }
  next();
};

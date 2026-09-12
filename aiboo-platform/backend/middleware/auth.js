import jwt from 'jsonwebtoken';

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

export const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (isBlacklisted(token)) {
      return res.status(401).json({ message: 'Token revoked' });
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
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

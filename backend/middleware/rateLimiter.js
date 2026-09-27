import rateLimit from 'express-rate-limit';

// ──────────────────────────────────────────────
// Auth limiter – stricter (20 attempts per 15 min)
// ──────────────────────────────────────────────
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: { message: 'Too many auth attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting in development
        return process.env.NODE_ENV === 'development';
    },
});

// ──────────────────────────────────────────────
// API limiter – for general API endpoints
// ──────────────────────────────────────────────
export const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // ✅ Increased from 100 to 200
    message: { message: 'Too many requests from this IP, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting entirely in development
        if (process.env.NODE_ENV === 'development') {
            return true;
        }
        // Also skip for agent health checks (keep them unblocked)
        if (req.path === '/health' || req.path === '/') {
            return true;
        }
        return false;
    },
});

// ──────────────────────────────────────────────
// Agent-specific limiter – higher limit for agents
// Since agents poll frequently, give them more room.
// ──────────────────────────────────────────────
export const agentLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute (shorter window)
    max: 60, // 60 requests per minute = 1 request per second
    message: { message: 'Too many agent requests, please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip in development
        return process.env.NODE_ENV === 'development';
    },
});

// ──────────────────────────────────────────────
// Per-IP limiter – for agent polling commands
// ──────────────────────────────────────────────
export const commandLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 commands per minute
    message: { message: 'Too many command requests, please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        return process.env.NODE_ENV === 'development';
    },
});
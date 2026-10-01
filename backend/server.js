import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import hpp from 'hpp';
import http from 'http';

import { connectDB } from './config/db.js';
import { initSocket } from './config/socket.js';
import socketHandler from './sockets/index.js';
import { registerAgentChannel } from './sockets/agentChannel.js';
import { errorHandler } from './middleware/error.js';
// ✅ Import all limiters (auth, api, agent)
import { authLimiter, apiLimiter, agentLimiter } from './middleware/rateLimiter.js';
import logger from './utils/logger.js';
import User from './models/User.js';
import { warnAboutDefaultPasswords } from './utils/passwords.js';

import authRoutes from './routes/auth.routes.js';
import threatRoutes from './routes/threat.routes.js';
import cameraRoutes from './routes/camera.routes.js';
import assetRoutes from './routes/asset.routes.js';
import identityRoutes from './routes/identity.routes.js';
import responseRoutes from './routes/response.routes.js';
import aiRoutes from './routes/ai.routes.js';
import dashboardRoutes from './routes/dashboard.routes.js';
import agentRoutes from './routes/agent.routes.js';
import { seedDemoAgentData } from './routes/agent.routes.js';
import alertRoutes from './routes/alert.routes.js';
import analyticsRoutes from './routes/analytics.routes.js';
import reportRoutes from './routes/report.routes.js';

// ❌ Outbound WebSocket import removed – agents push via HTTP.
// ✅ Inbound agent command channel added – dashboard → agent dispatch.

const app = express();

// ---- CORS configuration ----
let corsOrigins;
if (process.env.NODE_ENV === 'development') {
  corsOrigins = '*';
} else {
  corsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:3000'];
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
    },
  },
}));
app.set('trust proxy', process.env.TRUST_PROXY || 1);

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
}));
app.use(hpp());
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  logger.info(`${req.method} ${req.originalUrl}`);
  next();
});

// ---- Health & root (no rate limiting) ----
app.get('/', (req, res) => res.json({ service: 'AiBoO Backend', status: 'running' }));
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ---- Routes with appropriate rate limiters ----
app.use('/api/auth', authLimiter, authRoutes);                // Strict (20 per 15min)
app.use('/api/threats', apiLimiter, threatRoutes);
app.use('/api/cameras', apiLimiter, cameraRoutes);
app.use('/api/assets', apiLimiter, assetRoutes);
app.use('/api/identities', apiLimiter, identityRoutes);
app.use('/api/respond', apiLimiter, responseRoutes);
app.use('/api/ai', apiLimiter, aiRoutes);
app.use('/api/dashboard', apiLimiter, dashboardRoutes);
app.use('/api/alerts', apiLimiter, alertRoutes);          // Alert management (ack / assign / close)
app.use('/api/analytics', apiLimiter, analyticsRoutes);  // Executive dashboard, charts, trends
app.use('/api/reports', apiLimiter, reportRoutes);       // Risk / compliance / executive (PDF, CSV)

// ✅ Agent routes now use agentLimiter (more permissive)
app.use('/api/agent', agentLimiter, agentRoutes);

// ---- 404 & error handling ----
app.use((req, res) => res.status(404).json({ message: 'Endpoint not found' }));
app.use(errorHandler);

// ---- Socket.io setup ----
const server = http.createServer(app);
const io = initSocket(server);
socketHandler(io);

// ✅ Register the agent command channel on its own namespace (/agent-channel).
// Remote agents connect here so the dashboard can dispatch actions to them.
// The returned object is stored on the express app so routes can reach it
// via req.app.get('agentChannel').
const agentChannel = registerAgentChannel(io);
app.set('agentChannel', agentChannel);
logger.info('Agent command channel registered on /agent-channel namespace');

// ❌ Outbound WebSocket connection to agent is completely removed.
// Remote agents push findings via HTTP POST to /api/agent/findings.
// ✅ Inbound command channel added — see sockets/agentChannel.js.

// ---- Start server ----
const PORT = process.env.PORT || 4000;

const startServer = async () => {
  try {
    await connectDB();
    // Warn (in this log) about accounts that still use admin123 / analyst123.
    warnAboutDefaultPasswords(User, logger);
    // Sample findings/locks/actions are OFF unless explicitly requested, so a
    // fresh install only ever shows what real agents report.
    if (process.env.SEED_DEMO_DATA === 'true') {
      seedDemoAgentData();
    } else {
      logger.info('Demo data off - dashboard shows only real agent data (set SEED_DEMO_DATA=true for samples)');
    }
    server.listen(PORT, () => {
      logger.info(`AiBoO Backend running on port ${PORT}`);
      logger.info(`Agent command channel: ws://localhost:${PORT}/agent-channel`);
    });
  } catch (error) {
    logger.error(`Server start failed: ${error.message}`);
    process.exit(1);
  }
};

// ---- Graceful shutdown ----
const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received. Shutting down gracefully...`);
  server.close(() => {
    logger.info('HTTP server closed');
  });
  const mongoose = (await import('mongoose')).default;
  await mongoose.connection.close();
  logger.info('MongoDB connection closed');
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
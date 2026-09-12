import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import hpp from 'hpp';
import http from 'http';

import { connectDB } from './config/db.js';
import { initSocket } from './config/socket.js';
import socketHandler from './sockets/index.js';
import { errorHandler } from './middleware/error.js';
// ✅ Import all limiters (auth, api, agent)
import { authLimiter, apiLimiter, agentLimiter } from './middleware/rateLimiter.js';
import logger from './utils/logger.js';

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

// ❌ Outbound WebSocket import removed – agents push via HTTP.

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

// ✅ Agent routes now use agentLimiter (more permissive)
app.use('/api/agent', agentLimiter, agentRoutes);

// ---- 404 & error handling ----
app.use((req, res) => res.status(404).json({ message: 'Endpoint not found' }));
app.use(errorHandler);

// ---- Socket.io setup ----
const server = http.createServer(app);
const io = initSocket(server);
socketHandler(io);

// ❌ Outbound WebSocket connection to agent is completely removed.
// Remote agents push findings via HTTP POST to /api/agent/findings.

// ---- Start server ----
const PORT = process.env.PORT || 4000;

const startServer = async () => {
  try {
    await connectDB();
    if (process.env.NODE_ENV !== 'production' || process.env.SEED_DEMO_DATA === 'true') {
      seedDemoAgentData();
    }
    server.listen(PORT, () => {
      logger.info(`AiBoO Backend running on port ${PORT}`);
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
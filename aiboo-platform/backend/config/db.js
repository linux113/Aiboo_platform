import mongoose from 'mongoose';
import logger from '../utils/logger.js';

const MAX_RETRIES = 5;
const RETRY_DELAY = 5000;

export const connectDB = async (retryCount = 0) => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    logger.info('MongoDB connected');
  } catch (error) {
    logger.error(`DB connection error: ${error.message}`);
    if (retryCount < MAX_RETRIES) {
      logger.info(`Retrying connection in ${RETRY_DELAY}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      return connectDB(retryCount + 1);
    }
    logger.error('Max retries reached. Exiting.');
    process.exit(1);
  }
};

mongoose.connection.on('connected', () => {
  logger.info('Mongoose connected');
});

mongoose.connection.on('disconnected', () => {
  logger.warn('Mongoose disconnected');
});

mongoose.connection.on('reconnected', () => {
  logger.info('Mongoose reconnected');
});

mongoose.connection.on('error', (err) => {
  logger.error(`Mongoose error: ${err.message}`);
});

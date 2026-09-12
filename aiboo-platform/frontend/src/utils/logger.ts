type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const currentLevel: LogLevel =
  (import.meta.env.VITE_LOG_LEVEL as LogLevel) || "info";

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}

function timestamp(): string {
  return new Date().toISOString();
}

export const logger = {
  debug: (...args: unknown[]) => {
    if (shouldLog("debug")) console.debug(`[${timestamp()}] [DEBUG]`, ...args);
  },
  info: (...args: unknown[]) => {
    if (shouldLog("info")) console.info(`[${timestamp()}] [INFO]`, ...args);
  },
  warn: (...args: unknown[]) => {
    if (shouldLog("warn")) console.warn(`[${timestamp()}] [WARN]`, ...args);
  },
  error: (...args: unknown[]) => {
    if (shouldLog("error")) console.error(`[${timestamp()}] [ERROR]`, ...args);
  },
};

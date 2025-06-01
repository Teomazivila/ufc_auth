import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// Add colors to winston
winston.addColors(colors);

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...meta } = info;
    const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaString}`;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');

// Define transports
const transports = [
  // Console transport
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
    format: consoleFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // Error log file
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    handleExceptions: true,
    handleRejections: true
  }),

  // Combined log file
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    format: fileFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5
  })
];

// Add daily rotate file transport for production
if (process.env.NODE_ENV === 'production') {
  // Note: We'll use regular File transport for now since we don't have winston-daily-rotate-file
  // In a real project, you would install and use winston-daily-rotate-file
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'app-%DATE%.log'),
      format: fileFormat,
      maxsize: 20971520, // 20MB
      maxFiles: '14d' // Keep logs for 14 days
    })
  );
}

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] })
  ),
  transports,
  exitOnError: false,
  silent: process.env.NODE_ENV === 'test'
});

// Create a stream object for Morgan HTTP logging
logger.stream = {
  write: (message) => {
    logger.http(message.trim());
  }
};

// Helper methods for structured logging
logger.logRequest = (req, res, responseTime) => {
  const logData = {
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    userId: req.user?.id || null
  };

  if (res.statusCode >= 400) {
    logger.warn('HTTP Request', logData);
  } else {
    logger.info('HTTP Request', logData);
  }
};

logger.logError = (error, req = null, additionalInfo = {}) => {
  const errorData = {
    message: error.message,
    stack: error.stack,
    name: error.name,
    ...additionalInfo
  };

  if (req) {
    errorData.request = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
      params: req.params,
      query: req.query,
      ip: req.ip || req.connection.remoteAddress,
      userId: req.user?.id || null
    };
  }

  logger.error('Application Error', errorData);
};

logger.logSecurity = (event, req, additionalInfo = {}) => {
  const securityData = {
    event,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    url: req.originalUrl,
    method: req.method,
    userId: req.user?.id || null,
    timestamp: new Date().toISOString(),
    ...additionalInfo
  };

  logger.warn('Security Event', securityData);
};

logger.logAuth = (action, userId, req, success = true, additionalInfo = {}) => {
  const authData = {
    action,
    userId,
    success,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString(),
    ...additionalInfo
  };

  if (success) {
    logger.info('Authentication Event', authData);
  } else {
    logger.warn('Authentication Failure', authData);
  }
};

logger.logDatabase = (operation, table, success = true, duration = null, additionalInfo = {}) => {
  const dbData = {
    operation,
    table,
    success,
    duration: duration ? `${duration}ms` : null,
    timestamp: new Date().toISOString(),
    ...additionalInfo
  };

  if (success) {
    logger.debug('Database Operation', dbData);
  } else {
    logger.error('Database Error', dbData);
  }
};

// Performance monitoring
logger.performance = {
  start: (label) => {
    const start = process.hrtime.bigint();
    return {
      end: (additionalInfo = {}) => {
        const end = process.hrtime.bigint();
        const duration = Number(end - start) / 1000000; // Convert to milliseconds
        
        logger.debug('Performance Metric', {
          label,
          duration: `${duration.toFixed(2)}ms`,
          timestamp: new Date().toISOString(),
          ...additionalInfo
        });
        
        return duration;
      }
    };
  }
};

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, closing logger...');
  logger.end();
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, closing logger...');
  logger.end();
});

export default logger; 
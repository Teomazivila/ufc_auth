import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';

// Load environment variables
dotenv.config();

/**
 * Validates and converts environment variable to number
 * @param {string} value - Environment variable value
 * @param {number} defaultValue - Default value if conversion fails
 * @returns {number} Converted number or default
 */
const toNumber = (value, defaultValue) => {
  const num = parseInt(value, 10);
  return isNaN(num) ? defaultValue : num;
};

/**
 * Validates and converts environment variable to boolean
 * @param {string} value - Environment variable value
 * @param {boolean} defaultValue - Default value if conversion fails
 * @returns {boolean} Converted boolean or default
 */
const toBoolean = (value, defaultValue) => {
  if (value === undefined || value === null) return defaultValue;
  return value.toLowerCase() === 'true';
};

/**
 * Validates required environment variables
 * @param {Object} config - Configuration object
 */
const validateConfig = (config) => {
  const requiredFields = [
    'nodeEnv',
    'port',
    'database.host',
    'database.port',
    'database.name',
    'database.user',
    'jwt.secret',
    'jwt.refreshSecret'
  ];

  const missingFields = [];

  requiredFields.forEach(field => {
    const keys = field.split('.');
    let value = config;
    
    for (const key of keys) {
      value = value?.[key];
    }
    
    if (!value) {
      missingFields.push(field);
    }
  });

  if (missingFields.length > 0) {
    logger.error('Missing required environment variables:', missingFields);
    throw new Error(`Missing required environment variables: ${missingFields.join(', ')}`);
  }

  // Validate JWT secrets length
  if (config.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  if (config.jwt.refreshSecret.length < 32) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }
};

// Configuration object
export const config = {
  // Application
  nodeEnv: process.env.NODE_ENV || 'development',
  port: toNumber(process.env.PORT, 3000),
  apiVersion: process.env.API_VERSION || 'v1',

  // Database
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: toNumber(process.env.DB_PORT, 5432),
    name: process.env.DB_NAME || 'ufc_auth',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    ssl: toBoolean(process.env.DB_SSL, false),
    pool: {
      min: toNumber(process.env.DB_POOL_MIN, 2),
      max: toNumber(process.env.DB_POOL_MAX, 10),
      acquireTimeoutMillis: 60000,
      createTimeoutMillis: 30000,
      destroyTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
      reapIntervalMillis: 1000,
      createRetryIntervalMillis: 100
    }
  },

  // Redis
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: toNumber(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || '',
    db: toNumber(process.env.REDIS_DB, 0),
    ttl: toNumber(process.env.REDIS_TTL, 3600),
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: 3
  },

  // JWT
  jwt: {
    secret: process.env.JWT_SECRET || '',
    refreshSecret: process.env.JWT_REFRESH_SECRET || '',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'ufc-auth-api',
    audience: 'ufc-auth-client'
  },

  // Security
  security: {
    bcryptRounds: toNumber(process.env.BCRYPT_ROUNDS, 12),
    sessionSecret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
    sessionMaxAge: toNumber(process.env.SESSION_MAX_AGE, 86400000) // 24 hours
  },

  // Rate Limiting
  rateLimit: {
    windowMs: toNumber(process.env.RATE_LIMIT_WINDOW_MS, 900000), // 15 minutes
    maxRequests: toNumber(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
    skipSuccessfulRequests: toBoolean(process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS, true)
  },

  // Email
  email: {
    host: process.env.EMAIL_HOST || 'localhost',
    port: toNumber(process.env.EMAIL_PORT, 1025),
    secure: toBoolean(process.env.EMAIL_SECURE, false),
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
    from: process.env.EMAIL_FROM || 'noreply@ufcauth.com',
    fromName: process.env.EMAIL_FROM_NAME || 'UFC Auth System'
  },

  // 2FA
  twoFactor: {
    serviceName: process.env.TOTP_SERVICE_NAME || 'UFC Auth',
    issuer: process.env.TOTP_ISSUER || 'UFC Auth System',
    window: toNumber(process.env.TOTP_WINDOW, 2)
  },

  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.LOG_FORMAT || 'combined',
    file: process.env.LOG_FILE || 'logs/app.log',
    maxSize: process.env.LOG_MAX_SIZE || '10m',
    maxFiles: toNumber(process.env.LOG_MAX_FILES, 5)
  },

  // CORS
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: toBoolean(process.env.CORS_CREDENTIALS, true)
  },

  // File Upload
  upload: {
    maxSize: toNumber(process.env.UPLOAD_MAX_SIZE, 5242880), // 5MB
    allowedTypes: process.env.UPLOAD_ALLOWED_TYPES?.split(',') || ['image/jpeg', 'image/png', 'image/gif']
  },

  // API Documentation
  swagger: {
    title: process.env.SWAGGER_TITLE || 'UFC Auth API',
    description: process.env.SWAGGER_DESCRIPTION || 'API REST de Gestão de Identidades com Autenticação Forte',
    version: process.env.SWAGGER_VERSION || '1.0.0',
    contact: {
      name: process.env.SWAGGER_CONTACT_NAME || 'UFC Auth Team',
      email: process.env.SWAGGER_CONTACT_EMAIL || 'support@ufcauth.com'
    }
  },

  // Health Check
  healthCheck: {
    timeout: toNumber(process.env.HEALTH_CHECK_TIMEOUT, 5000),
    interval: toNumber(process.env.HEALTH_CHECK_INTERVAL, 30000)
  },

  // Development
  development: {
    enableSwagger: toBoolean(process.env.DEV_ENABLE_SWAGGER, true),
    enableCors: toBoolean(process.env.DEV_ENABLE_CORS, true),
    enableMorgan: toBoolean(process.env.DEV_ENABLE_MORGAN, true)
  }
};

// Validate configuration
try {
  validateConfig(config);
  logger.info('Configuration loaded successfully', {
    environment: config.nodeEnv,
    port: config.port,
    database: config.database.name
  });
} catch (error) {
  logger.error('Configuration validation failed:', error.message);
  process.exit(1);
}

export default config; 
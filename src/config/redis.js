import { createClient } from 'redis';
import { config } from './index.js';
import { logger } from '../utils/logger.js';

let redisClient = null;

/**
 * Redis connection configuration
 */
const redisConfig = {
  socket: {
    host: config.redis.host,
    port: config.redis.port,
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        logger.error('Redis reconnection failed after 10 attempts');
        return new Error('Redis reconnection failed');
      }
      const delay = Math.min(retries * 50, 500);
      logger.warn(`Redis reconnecting in ${delay}ms (attempt ${retries})`);
      return delay;
    }
  },
  password: config.redis.password || undefined,
  database: config.redis.db,
  retryDelayOnFailover: config.redis.retryDelayOnFailover,
  enableReadyCheck: config.redis.enableReadyCheck,
  maxRetriesPerRequest: config.redis.maxRetriesPerRequest
};

/**
 * Create Redis client
 */
const createRedisClient = () => {
  if (redisClient) {
    return redisClient;
  }

  redisClient = createClient(redisConfig);

  // Event handlers
  redisClient.on('connect', () => {
    logger.info('Redis client connecting...', {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db
    });
  });

  redisClient.on('ready', () => {
    logger.info('Redis client ready', {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db
    });
  });

  redisClient.on('error', (error) => {
    logger.error('Redis client error:', {
      error: error.message,
      host: config.redis.host,
      port: config.redis.port
    });
  });

  redisClient.on('end', () => {
    logger.info('Redis client connection ended');
  });

  redisClient.on('reconnecting', () => {
    logger.warn('Redis client reconnecting...');
  });

  return redisClient;
};

/**
 * Connect to Redis
 */
export const connectRedis = async () => {
  try {
    const startTime = Date.now();

    // Create client if it doesn't exist
    if (!redisClient) {
      createRedisClient();
    }

    // Connect to Redis
    await redisClient.connect();

    // Test connection
    const pong = await redisClient.ping();
    const connectionTime = Date.now() - startTime;

    logger.info('Redis connected successfully', {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db,
      connectionTime: `${connectionTime}ms`,
      ping: pong
    });

    return redisClient;
  } catch (error) {
    logger.error('Failed to connect to Redis:', {
      error: error.message,
      host: config.redis.host,
      port: config.redis.port
    });
    throw error;
  }
};

/**
 * Get Redis client instance
 */
export const getRedisClient = () => {
  if (!redisClient || !redisClient.isReady) {
    throw new Error('Redis client not initialized or not ready. Call connectRedis() first.');
  }
  return redisClient;
};

/**
 * Set a key-value pair with optional TTL
 */
export const set = async (key, value, ttl = config.redis.ttl) => {
  try {
    const client = getRedisClient();
    const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value;
    
    if (ttl) {
      await client.setEx(key, ttl, serializedValue);
    } else {
      await client.set(key, serializedValue);
    }
    
    logger.debug('Redis SET operation', { key, ttl });
  } catch (error) {
    logger.error('Redis SET error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Get a value by key
 */
export const get = async (key) => {
  try {
    const client = getRedisClient();
    const value = await client.get(key);
    
    if (value === null) {
      logger.debug('Redis GET operation - key not found', { key });
      return null;
    }
    
    // Try to parse as JSON, fallback to string
    try {
      const parsed = JSON.parse(value);
      logger.debug('Redis GET operation - JSON parsed', { key });
      return parsed;
    } catch {
      logger.debug('Redis GET operation - string value', { key });
      return value;
    }
  } catch (error) {
    logger.error('Redis GET error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Delete a key
 */
export const del = async (key) => {
  try {
    const client = getRedisClient();
    const result = await client.del(key);
    logger.debug('Redis DEL operation', { key, deleted: result });
    return result;
  } catch (error) {
    logger.error('Redis DEL error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Check if key exists
 */
export const exists = async (key) => {
  try {
    const client = getRedisClient();
    const result = await client.exists(key);
    logger.debug('Redis EXISTS operation', { key, exists: !!result });
    return !!result;
  } catch (error) {
    logger.error('Redis EXISTS error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Set expiration for a key
 */
export const expire = async (key, ttl) => {
  try {
    const client = getRedisClient();
    const result = await client.expire(key, ttl);
    logger.debug('Redis EXPIRE operation', { key, ttl, success: !!result });
    return !!result;
  } catch (error) {
    logger.error('Redis EXPIRE error:', { key, ttl, error: error.message });
    throw error;
  }
};

/**
 * Get TTL for a key
 */
export const ttl = async (key) => {
  try {
    const client = getRedisClient();
    const result = await client.ttl(key);
    logger.debug('Redis TTL operation', { key, ttl: result });
    return result;
  } catch (error) {
    logger.error('Redis TTL error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Increment a numeric value
 */
export const incr = async (key) => {
  try {
    const client = getRedisClient();
    const result = await client.incr(key);
    logger.debug('Redis INCR operation', { key, value: result });
    return result;
  } catch (error) {
    logger.error('Redis INCR error:', { key, error: error.message });
    throw error;
  }
};

/**
 * Increment by a specific amount
 */
export const incrBy = async (key, increment) => {
  try {
    const client = getRedisClient();
    const result = await client.incrBy(key, increment);
    logger.debug('Redis INCRBY operation', { key, increment, value: result });
    return result;
  } catch (error) {
    logger.error('Redis INCRBY error:', { key, increment, error: error.message });
    throw error;
  }
};

/**
 * Check Redis health
 */
export const checkHealth = async () => {
  try {
    if (!redisClient || !redisClient.isReady) {
      return {
        status: 'unhealthy',
        error: 'Redis client not ready'
      };
    }

    const startTime = Date.now();
    const pong = await redisClient.ping();
    const responseTime = Date.now() - startTime;

    return {
      status: 'healthy',
      responseTime: `${responseTime}ms`,
      ping: pong,
      isReady: redisClient.isReady,
      isOpen: redisClient.isOpen
    };
  } catch (error) {
    logger.error('Redis health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
};

/**
 * Get Redis statistics
 */
export const getStats = async () => {
  try {
    if (!redisClient || !redisClient.isReady) {
      return {
        status: 'disconnected'
      };
    }

    const info = await redisClient.info();
    const memory = await redisClient.info('memory');
    
    return {
      status: 'connected',
      isReady: redisClient.isReady,
      isOpen: redisClient.isOpen,
      config: {
        host: config.redis.host,
        port: config.redis.port,
        database: config.redis.db
      },
      info: {
        server: info,
        memory: memory
      }
    };
  } catch (error) {
    logger.error('Error getting Redis stats:', error);
    return {
      status: 'error',
      error: error.message
    };
  }
};

/**
 * Close Redis connection
 */
export const closeRedis = async () => {
  if (redisClient) {
    try {
      await redisClient.quit();
      redisClient = null;
      logger.info('Redis connection closed');
    } catch (error) {
      logger.error('Error closing Redis connection:', error);
      throw error;
    }
  }
};

/**
 * Redis utility functions
 */
export const redis = {
  set,
  get,
  del,
  exists,
  expire,
  ttl,
  incr,
  incrBy,
  checkHealth,
  getStats,
  getClient: getRedisClient,
  close: closeRedis
};

export default redis; 
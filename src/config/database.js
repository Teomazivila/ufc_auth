import pkg from 'pg';
import { config } from './index.js';
import { logger } from '../utils/logger.js';

const { Pool } = pkg;

let pool = null;

/**
 * Database connection configuration
 */
const dbConfig = {
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  ssl: config.database.ssl ? { rejectUnauthorized: false } : false,
  ...config.database.pool
};

/**
 * Create and configure database connection pool
 */
const createPool = () => {
  if (pool) {
    return pool;
  }

  pool = new Pool(dbConfig);

  // Handle pool errors
  pool.on('error', (err) => {
    logger.error('Unexpected error on idle client', err);
  });

  // Handle pool connection events
  pool.on('connect', (client) => {
    logger.debug('New client connected to database', {
      totalCount: pool.totalCount,
      idleCount: pool.idleCount,
      waitingCount: pool.waitingCount
    });
  });

  pool.on('acquire', (client) => {
    logger.debug('Client acquired from pool', {
      totalCount: pool.totalCount,
      idleCount: pool.idleCount,
      waitingCount: pool.waitingCount
    });
  });

  pool.on('remove', (client) => {
    logger.debug('Client removed from pool', {
      totalCount: pool.totalCount,
      idleCount: pool.idleCount,
      waitingCount: pool.waitingCount
    });
  });

  return pool;
};

/**
 * Connect to database and test connection
 */
export const connectDatabase = async () => {
  try {
    const startTime = Date.now();
    
    // Create pool if it doesn't exist
    if (!pool) {
      createPool();
    }

    // Test connection
    const client = await pool.connect();
    const result = await client.query('SELECT NOW() as current_time, version() as version');
    client.release();

    const connectionTime = Date.now() - startTime;

    logger.info('Database connected successfully', {
      host: config.database.host,
      database: config.database.name,
      connectionTime: `${connectionTime}ms`,
      version: result.rows[0].version.split(' ')[0],
      currentTime: result.rows[0].current_time
    });

    return pool;
  } catch (error) {
    logger.error('Failed to connect to database:', {
      error: error.message,
      host: config.database.host,
      database: config.database.name,
      port: config.database.port
    });
    throw error;
  }
};

/**
 * Get database pool instance
 */
export const getPool = () => {
  if (!pool) {
    throw new Error('Database pool not initialized. Call connectDatabase() first.');
  }
  return pool;
};

/**
 * Execute a query with automatic connection handling
 */
export const query = async (text, params = []) => {
  // Ensure pool is initialized
  if (!pool) {
    throw new Error('Database pool not initialized. Call connectDatabase() first.');
  }
  
  const startTime = Date.now();
  const client = await pool.connect();
  
  try {
    const result = await client.query(text, params);
    const duration = Date.now() - startTime;
    
    logger.logDatabase('query', 'unknown', true, duration, {
      rowCount: result.rowCount,
      command: result.command
    });
    
    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.logDatabase('query', 'unknown', false, duration, {
      error: error.message,
      query: text.substring(0, 100) + (text.length > 100 ? '...' : '')
    });
    
    throw error;
  } finally {
    client.release();
  }
};

/**
 * Execute a transaction
 */
export const transaction = async (callback) => {
  const client = await pool.connect();
  const startTime = Date.now();
  
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    
    const duration = Date.now() - startTime;
    logger.logDatabase('transaction', 'multiple', true, duration);
    
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    
    const duration = Date.now() - startTime;
    logger.logDatabase('transaction', 'multiple', false, duration, {
      error: error.message
    });
    
    throw error;
  } finally {
    client.release();
  }
};

/**
 * Check database health
 */
export const checkHealth = async () => {
  try {
    const startTime = Date.now();
    const result = await query('SELECT 1 as health_check');
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'healthy',
      responseTime: `${responseTime}ms`,
      connections: {
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount
      }
    };
  } catch (error) {
    logger.error('Database health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
};

/**
 * Get database statistics
 */
export const getStats = () => {
  if (!pool) {
    return {
      status: 'disconnected'
    };
  }

  return {
    status: 'connected',
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount,
    config: {
      host: config.database.host,
      database: config.database.name,
      port: config.database.port,
      maxConnections: config.database.pool.max,
      minConnections: config.database.pool.min
    }
  };
};

/**
 * Close database connection pool
 */
export const closeDatabase = async () => {
  if (pool) {
    try {
      await pool.end();
      pool = null;
      logger.info('Database connection pool closed');
    } catch (error) {
      logger.error('Error closing database pool:', error);
      throw error;
    }
  }
};

/**
 * Database utility functions
 */
export const db = {
  query,
  transaction,
  getPool,
  checkHealth,
  getStats,
  close: closeDatabase
};

export default db; 
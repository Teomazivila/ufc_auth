import { Router } from 'express';
import { asyncHandler } from '../middleware/errorHandler.js';
import { checkHealth as checkDatabaseHealth, getStats as getDatabaseStats } from '../config/database.js';
import { checkHealth as checkRedisHealth, getStats as getRedisStats } from '../config/redis.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

const router = Router();

/**
 * Basic health check
 * GET /health
 */
router.get('/', asyncHandler(async (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.nodeEnv,
    version: '1.0.0'
  };

  res.json(health);
}));

/**
 * Detailed health check with dependencies
 * GET /health/detailed
 */
router.get('/detailed', asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  // Check all dependencies
  const [databaseHealth, redisHealth] = await Promise.allSettled([
    checkDatabaseHealth(),
    checkRedisHealth()
  ]);

  // Determine overall status
  const isHealthy = 
    databaseHealth.status === 'fulfilled' && databaseHealth.value.status === 'healthy' &&
    redisHealth.status === 'fulfilled' && redisHealth.value.status === 'healthy';

  const health = {
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.nodeEnv,
    version: '1.0.0',
    responseTime: `${Date.now() - startTime}ms`,
    dependencies: {
      database: databaseHealth.status === 'fulfilled' 
        ? databaseHealth.value 
        : { status: 'unhealthy', error: databaseHealth.reason?.message },
      redis: redisHealth.status === 'fulfilled' 
        ? redisHealth.value 
        : { status: 'unhealthy', error: redisHealth.reason?.message }
    },
    system: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        external: Math.round(process.memoryUsage().external / 1024 / 1024),
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
      },
      cpu: process.cpuUsage()
    }
  };

  // Set appropriate status code
  const statusCode = isHealthy ? 200 : 503;

  res.status(statusCode).json({
    success: isHealthy,
    data: health
  });
}));

/**
 * Database health check
 * GET /health/database
 */
router.get('/database', asyncHandler(async (req, res) => {
  const health = await checkDatabaseHealth();
  const stats = getDatabaseStats();
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  
  res.status(statusCode).json({
    success: health.status === 'healthy',
    data: {
      ...health,
      stats
    }
  });
}));

/**
 * Redis health check
 * GET /health/redis
 */
router.get('/redis', asyncHandler(async (req, res) => {
  const health = await checkRedisHealth();
  const stats = await getRedisStats();
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  
  res.status(statusCode).json({
    success: health.status === 'healthy',
    data: {
      ...health,
      stats
    }
  });
}));

/**
 * Readiness probe (for Kubernetes)
 * GET /health/ready
 */
router.get('/ready', asyncHandler(async (req, res) => {
  try {
    // Check if all critical dependencies are ready
    const [databaseHealth, redisHealth] = await Promise.all([
      checkDatabaseHealth(),
      checkRedisHealth()
    ]);

    const isReady = 
      databaseHealth.status === 'healthy' && 
      redisHealth.status === 'healthy';

    if (isReady) {
      res.json({
        success: true,
        data: {
          status: 'ready',
          timestamp: new Date().toISOString()
        }
      });
    } else {
      res.status(503).json({
        success: false,
        error: {
          code: 'NOT_READY',
          message: 'Service not ready',
          timestamp: new Date().toISOString()
        }
      });
    }
  } catch (error) {
    logger.error('Readiness check failed:', error);
    res.status(503).json({
      success: false,
      error: {
        code: 'READINESS_CHECK_FAILED',
        message: 'Readiness check failed',
        timestamp: new Date().toISOString()
      }
    });
  }
}));

/**
 * Liveness probe (for Kubernetes)
 * GET /health/live
 */
router.get('/live', asyncHandler(async (req, res) => {
  // Simple liveness check - just verify the process is running
  res.json({
    success: true,
    data: {
      status: 'alive',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      pid: process.pid
    }
  });
}));

/**
 * Startup probe (for Kubernetes)
 * GET /health/startup
 */
router.get('/startup', asyncHandler(async (req, res) => {
  try {
    // Check if application has started successfully
    const [databaseHealth, redisHealth] = await Promise.all([
      checkDatabaseHealth(),
      checkRedisHealth()
    ]);

    const hasStarted = 
      databaseHealth.status === 'healthy' && 
      redisHealth.status === 'healthy';

    if (hasStarted) {
      res.json({
        success: true,
        data: {
          status: 'started',
          timestamp: new Date().toISOString(),
          uptime: process.uptime()
        }
      });
    } else {
      res.status(503).json({
        success: false,
        error: {
          code: 'NOT_STARTED',
          message: 'Service not started',
          timestamp: new Date().toISOString()
        }
      });
    }
  } catch (error) {
    logger.error('Startup check failed:', error);
    res.status(503).json({
      success: false,
      error: {
        code: 'STARTUP_CHECK_FAILED',
        message: 'Startup check failed',
        timestamp: new Date().toISOString()
      }
    });
  }
}));

/**
 * System metrics
 * GET /health/metrics
 */
router.get('/metrics', asyncHandler(async (req, res) => {
  const metrics = {
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    system: {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      pid: process.pid
    },
    environment: {
      nodeEnv: config.nodeEnv,
      port: config.port
    }
  };

  res.json({
    success: true,
    data: metrics
  });
}));

export default router; 
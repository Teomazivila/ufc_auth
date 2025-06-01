import { Router } from 'express';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

// Import route modules
import healthRoutes from './health.js';
// TODO: Implement in Week 2
// import authRoutes from './auth.js';
// TODO: Implement in Week 3
// import userRoutes from './users.js';

const router = Router();

/**
 * API Routes Configuration
 */

// Health check routes (no versioning needed)
router.use('/health', healthRoutes);

// API v1 routes
const v1Router = Router();

// TODO: Authentication routes (Week 2)
// v1Router.use('/auth', authRoutes);

// TODO: User management routes (Week 3)
// v1Router.use('/users', userRoutes);

// Mount v1 routes
router.use('/api/v1', v1Router);

// API information endpoint
router.get('/api', (req, res) => {
  res.json({
    success: true,
    data: {
      name: 'UFC Auth API',
      version: '1.0.0',
      description: 'Identity Management API with Strong Authentication',
      environment: config.nodeEnv,
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        // TODO: Add auth endpoints in Week 2
        // auth: '/api/v1/auth',
        // TODO: Add user endpoints in Week 3
        // users: '/api/v1/users'
      },
      documentation: '/api/docs',
      status: 'operational'
    }
  });
});

// Log route registration
logger.info('API routes registered', {
  version: 'v1',
  routes: [
    'GET /api',
    'GET /health/*'
    // TODO: Add more routes in upcoming weeks
    // 'POST /api/v1/auth/*',
    // 'GET /api/v1/users/*'
  ]
});

export default router; 
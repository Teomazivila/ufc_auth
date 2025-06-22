import { Router } from 'express';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

// Import route modules
import healthRoutes from './health.js';
import authRoutes from './auth.js';
// Week 3: RBAC routes
import roleRoutes from './roleRoutes.js';
import permissionRoutes from './permissionRoutes.js';
import userManagementRoutes from './userManagementRoutes.js';
// Week 4: Audit routes
import auditRoutes from './auditRoutes.js';
// API Documentation routes
import swaggerRoutes from './swagger.js';

const router = Router();

/**
 * API Routes Configuration
 */

// Health check routes (no versioning needed)
router.use('/health', healthRoutes);

// API Documentation routes (no versioning needed)
router.use('/', swaggerRoutes);

// API v1 routes
const v1Router = Router();

// Authentication routes
v1Router.use('/auth', authRoutes);

// Week 3: RBAC routes
v1Router.use('/roles', roleRoutes);
v1Router.use('/permissions', permissionRoutes);
v1Router.use('/users', userManagementRoutes);

// Week 4: Audit routes
v1Router.use('/audit', auditRoutes);

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
        auth: '/api/v1/auth',
        users: '/api/v1/users',
        roles: '/api/v1/roles',
        permissions: '/api/v1/permissions',
        audit: '/api/v1/audit'
      },
      features: {
        authentication: 'JWT with refresh tokens',
        twoFactor: 'TOTP with backup codes',
        security: 'Rate limiting, account lockout, audit logging',
        authorization: 'RBAC (Role-Based Access Control)'
      },
      documentation: {
        swagger: '/api-docs', // ✅ Interactive Swagger UI
        openapi_json: '/api-docs/openapi.json', // ✅ OpenAPI JSON
        openapi_yaml: '/api-docs/openapi.yaml', // ✅ OpenAPI YAML
        postman: '/api-docs/postman', // ✅ Postman Collection
        redoc: '/api-docs/redoc' // ✅ Alternative ReDoc UI
      }
    }
  });
});

// Log route registration
logger.info('API routes registered', {
  version: 'v1',
  routes: [
    'GET /api',
    'GET /health/*',
    'POST /api/v1/auth/*',
    'GET /api/v1/users/*',
    'GET /api/v1/roles/*',
    'GET /api/v1/permissions/*'
  ]
});

export default router; 
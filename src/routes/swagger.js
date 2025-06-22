import { Router } from 'express';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec, swaggerUIOptions } from '../config/swagger.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

const router = Router();

/**
 * Swagger Documentation Routes
 * Following 2025 OpenAPI and Swagger UI best practices
 * 
 * Features:
 * - Interactive API documentation
 * - Multiple export formats (JSON, YAML)
 * - Custom styling and branding
 * - Authentication integration
 * - Performance optimized
 */

// Generate additional formats
const generateYAML = (spec) => {
  // Simple YAML conversion for basic needs
  // In production, use a proper YAML library like 'js-yaml'
  return JSON.stringify(spec, null, 2);
};

// Security middleware for documentation access
const documentationAccess = (req, res, next) => {
  // In development, allow unrestricted access
  if (config.nodeEnv === 'development') {
    return next();
  }
  
  // In production, you might want to restrict access
  // Uncomment and customize as needed:
  /*
  const apiKey = req.headers['x-api-key'];
  const authToken = req.headers.authorization;
  
  if (!apiKey && !authToken) {
    return res.status(401).json({
      success: false,
      message: 'Documentation access requires authentication',
      hint: 'Contact your administrator for API documentation access'
    });
  }
  */
  
  next();
};

/**
 * @swagger
 * /api-docs:
 *   get:
 *     tags: [System]
 *     summary: Interactive API Documentation
 *     description: Access the complete interactive API documentation powered by Swagger UI
 *     responses:
 *       200:
 *         description: Interactive documentation interface
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 */

// Main Swagger UI route
router.use('/api-docs', 
  documentationAccess,
  swaggerUi.serve,
  (req, res, next) => {
    // Add custom headers for security
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    
    // Log documentation access
    logger.info('API documentation accessed', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    
    next();
  },
  swaggerUi.setup(swaggerSpec, swaggerUIOptions)
);

/**
 * @swagger
 * /api-docs/openapi.json:
 *   get:
 *     tags: [System]
 *     summary: OpenAPI Specification (JSON)
 *     description: Download the complete OpenAPI 3.1 specification in JSON format
 *     responses:
 *       200:
 *         description: OpenAPI specification in JSON format
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *             examples:
 *               openapi:
 *                 summary: Complete API specification
 *                 value:
 *                   openapi: "3.1.0"
 *                   info:
 *                     title: "UFC Auth API"
 *                     version: "1.0.0"
 */

// OpenAPI spec in JSON format
router.get('/api-docs/openapi.json', documentationAccess, (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="openapi-spec.json"');
  
  // Add generation metadata
  const specWithMeta = {
    ...swaggerSpec,
    'x-generated-at': new Date().toISOString(),
    'x-generated-by': 'UFC Auth API Documentation Generator',
    'x-generator-version': '1.0.0'
  };
  
  logger.info('OpenAPI JSON spec downloaded', {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.json(specWithMeta);
});

/**
 * @swagger
 * /api-docs/openapi.yaml:
 *   get:
 *     tags: [System]
 *     summary: OpenAPI Specification (YAML)
 *     description: Download the complete OpenAPI 3.1 specification in YAML format
 *     responses:
 *       200:
 *         description: OpenAPI specification in YAML format
 *         content:
 *           application/x-yaml:
 *             schema:
 *               type: string
 */

// OpenAPI spec in YAML format
router.get('/api-docs/openapi.yaml', documentationAccess, (req, res) => {
  res.setHeader('Content-Type', 'application/x-yaml');
  res.setHeader('Content-Disposition', 'attachment; filename="openapi-spec.yaml"');
  
  const specWithMeta = {
    ...swaggerSpec,
    'x-generated-at': new Date().toISOString(),
    'x-generated-by': 'UFC Auth API Documentation Generator'
  };
  
  logger.info('OpenAPI YAML spec downloaded', {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.send(generateYAML(specWithMeta));
});

/**
 * @swagger
 * /api-docs/postman:
 *   get:
 *     tags: [System]
 *     summary: Postman Collection Export
 *     description: Download a Postman collection with all API endpoints and examples
 *     responses:
 *       200:
 *         description: Postman collection in JSON format
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

// Postman collection generator
router.get('/api-docs/postman', documentationAccess, (req, res) => {
  const postmanCollection = {
    info: {
      name: swaggerSpec.info.title,
      description: swaggerSpec.info.description,
      version: swaggerSpec.info.version,
      schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    auth: {
      type: "bearer",
      bearer: [
        {
          key: "token",
          value: "{{access_token}}",
          type: "string"
        }
      ]
    },
    variable: [
      {
        key: "base_url",
        value: "http://localhost:3000",
        type: "string"
      },
      {
        key: "access_token",
        value: "",
        type: "string"
      }
    ]
  };
  
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="ufc-auth-api.postman_collection.json"');
  
  logger.info('Postman collection downloaded', {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.json(postmanCollection);
});

/**
 * @swagger
 * /api-docs/redoc:
 *   get:
 *     tags: [System]
 *     summary: ReDoc Documentation
 *     description: Alternative documentation interface using ReDoc
 *     responses:
 *       200:
 *         description: ReDoc documentation interface
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 */

// Alternative ReDoc documentation
router.get('/api-docs/redoc', documentationAccess, (req, res) => {
  const redocHtml = `
<!DOCTYPE html>
<html>
  <head>
    <title>${swaggerSpec.info.title} - API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
      body { margin: 0; padding: 0; }
      redoc { display: block; }
    </style>
  </head>
  <body>
    <redoc spec-url='/api-docs/openapi.json'
           theme='{"colors": {"primary": {"main": "#3b82f6"}}}'
           hide-download-button='false'
           hide-hostname='false'
           expand-responses='200,201'
           required-props-first='true'
           sort-props-alphabetically='true'
           show-extensions='true'
           native-scrollbars='true'>
    </redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </body>
</html>`;
  
  res.setHeader('Content-Type', 'text/html');
  
  logger.info('ReDoc documentation accessed', {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.send(redocHtml);
});

/**
 * @swagger
 * /api-docs/health:
 *   get:
 *     tags: [System]
 *     summary: Documentation Service Health
 *     description: Check if the documentation service is working properly
 *     responses:
 *       200:
 *         description: Documentation service is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "healthy"
 *                 service:
 *                   type: string
 *                   example: "api-documentation"
 *                 version:
 *                   type: string
 *                   example: "1.0.0"
 *                 endpoints:
 *                   type: object
 */

// Documentation service health check
router.get('/api-docs/health', (req, res) => {
  const healthStatus = {
    status: 'healthy',
    service: 'api-documentation',
    version: swaggerSpec.info.version,
    timestamp: new Date().toISOString(),
    endpoints: {
      interactive: '/api-docs',
      json: '/api-docs/openapi.json',
      yaml: '/api-docs/openapi.yaml',
      postman: '/api-docs/postman',
      redoc: '/api-docs/redoc'
    },
    stats: {
      specGenerated: true,
      totalEndpoints: Object.keys(swaggerSpec.paths || {}).length,
      totalSchemas: Object.keys(swaggerSpec.components?.schemas || {}).length,
      securitySchemes: Object.keys(swaggerSpec.components?.securitySchemes || {}).length
    }
  };
  
  res.json(healthStatus);
});

/**
 * @swagger
 * /api-docs/stats:
 *   get:
 *     tags: [System]
 *     summary: API Documentation Statistics
 *     description: Get statistics about the API documentation and usage
 *     responses:
 *       200:
 *         description: Documentation statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

// Documentation statistics
router.get('/api-docs/stats', documentationAccess, (req, res) => {
  const stats = {
    api: {
      title: swaggerSpec.info.title,
      version: swaggerSpec.info.version,
      openApiVersion: swaggerSpec.openapi,
      totalPaths: Object.keys(swaggerSpec.paths || {}).length,
      totalSchemas: Object.keys(swaggerSpec.components?.schemas || {}).length,
      totalTags: (swaggerSpec.tags || []).length,
      securitySchemes: Object.keys(swaggerSpec.components?.securitySchemes || {}).length
    },
    endpoints: {
      byMethod: {},
      byTag: {},
      secured: 0,
      public: 0
    },
    lastGenerated: new Date().toISOString(),
    environment: config.nodeEnv
  };
  
  // Calculate endpoint statistics
  if (swaggerSpec.paths) {
    Object.entries(swaggerSpec.paths).forEach(([path, methods]) => {
      Object.entries(methods).forEach(([method, spec]) => {
        // Count by method
        stats.endpoints.byMethod[method] = (stats.endpoints.byMethod[method] || 0) + 1;
        
        // Count by tag
        if (spec.tags) {
          spec.tags.forEach(tag => {
            stats.endpoints.byTag[tag] = (stats.endpoints.byTag[tag] || 0) + 1;
          });
        }
        
        // Count security
        if (spec.security && spec.security.length > 0) {
          stats.endpoints.secured++;
        } else {
          stats.endpoints.public++;
        }
      });
    });
  }
  
  logger.info('Documentation stats requested', {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.json(stats);
});

// Handle favicon for documentation
router.get('/api-docs/favicon.ico', (req, res) => {
  // Send a simple 1x1 pixel favicon or redirect to your favicon URL
  res.status(204).end();
});

// Error handling for documentation routes
router.use('/api-docs*', (error, req, res, next) => {
  logger.error('Documentation route error:', error);
  
  res.status(500).json({
    success: false,
    message: 'Documentation service error',
    error: config.nodeEnv === 'development' ? error.message : 'Internal server error'
  });
});

export default router; 
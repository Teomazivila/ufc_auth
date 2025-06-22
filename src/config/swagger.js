import swaggerJsdoc from 'swagger-jsdoc';
import { config } from './index.js';

/**
 * Swagger Configuration for UFC Auth API
 * Following 2025 OpenAPI 3.1 Best Practices
 * 
 * @see https://swagger.io/specification/
 * @see https://swagger.io/tools/swagger-ui/
 */

// OpenAPI 3.1 specification (latest as of 2025)
const swaggerDefinition = {
  openapi: '3.1.0',
  info: {
    title: config.swagger.title,
    version: config.swagger.version,
    description: `${config.swagger.description}

## 🔐 **Authentication & Security**
This API implements enterprise-grade security with:
- **JWT Authentication** with refresh tokens
- **Multi-Factor Authentication (2FA)** via TOTP
- **Role-Based Access Control (RBAC)** with granular permissions
- **Rate Limiting** and brute force protection
- **Comprehensive Audit Logging**

## 🚀 **Getting Started**
1. Register a new account via \`POST /api/v1/auth/register\`
2. Activate your account (email verification)
3. Login via \`POST /api/v1/auth/login\`
4. Use the received JWT token in the \`Authorization\` header
5. Set up 2FA for enhanced security

## 📊 **API Standards**
- RESTful design principles
- JSON API specification compliance
- Consistent error handling
- Comprehensive input validation
- OWASP security guidelines compliance

## 🛡️ **Security Features**
- bcrypt password hashing (12 rounds)
- JWT with RS256 signing
- Account lockout after failed attempts
- IP-based rate limiting
- Session management with Redis
- Complete audit trail`,
    
    contact: {
      name: config.swagger.contact.name,
      email: config.swagger.contact.email,
      url: 'https://github.com/ufc-auth/api'
    },
    
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT'
    },
    
    termsOfService: 'https://ufcauth.com/terms',
    
    // API versioning strategy
    'x-api-version': '1.0.0',
    'x-api-status': 'stable',
    'x-last-modified': new Date().toISOString()
  },

  // Server configuration for different environments
  servers: [
    {
      url: 'http://localhost:3000',
      description: '🔧 Development Server',
      variables: {
        version: {
          default: 'v1',
          description: 'API version'
        }
      }
    },
    {
      url: 'https://api.ufcauth.com',
      description: '🚀 Production Server',
      variables: {
        version: {
          default: 'v1',
          description: 'API version'
        }
      }
    },
    {
      url: 'https://staging-api.ufcauth.com',
      description: '🧪 Staging Server',
      variables: {
        version: {
          default: 'v1',
          description: 'API version'
        }
      }
    }
  ],

  // Global path prefix
  'x-path-prefix': '/api/v1',

  // Security schemes following OAuth 2.0 and JWT best practices
  components: {
    securitySchemes: {
      // JWT Bearer token (primary authentication)
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: `
## JWT Authentication

Use the JWT token received from login endpoint:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

### Token Lifecycle:
- **Access Token**: 15 minutes validity
- **Refresh Token**: 7 days validity
- **Auto-refresh**: Use refresh endpoint before expiration
        `
      },

      // API Key authentication (for service-to-service)
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'API Key for service-to-service authentication'
      },

      // OAuth 2.0 flow (future implementation)
      OAuth2: {
        type: 'oauth2',
        description: 'OAuth 2.0 authorization code flow',
        flows: {
          authorizationCode: {
            authorizationUrl: '/oauth/authorize',
            tokenUrl: '/oauth/token',
            scopes: {
              'read:profile': 'Read user profile',
              'write:profile': 'Update user profile',
              'read:users': 'Read user information',
              'write:users': 'Manage users',
              'admin': 'Full administrative access'
            }
          }
        }
      }
    },

    // Reusable response schemas
    responses: {
      Success: {
        description: 'Operation successful',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: true },
                message: { type: 'string', example: 'Operation completed successfully' },
                data: { type: 'object' },
                meta: {
                  type: 'object',
                  properties: {
                    timestamp: { type: 'string', format: 'date-time' },
                    requestId: { type: 'string' },
                    version: { type: 'string' }
                  }
                }
              }
            }
          }
        }
      },

      ValidationError: {
        description: 'Validation error',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Validation failed' },
                errors: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      field: { type: 'string' },
                      message: { type: 'string' },
                      code: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      },

      Unauthorized: {
        description: 'Authentication required',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Authentication required' },
                code: { type: 'string', example: 'UNAUTHORIZED' }
              }
            }
          }
        }
      },

      Forbidden: {
        description: 'Insufficient permissions',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Insufficient permissions' },
                required_permission: { type: 'string' },
                code: { type: 'string', example: 'FORBIDDEN' }
              }
            }
          }
        }
      },

      NotFound: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Resource not found' },
                code: { type: 'string', example: 'NOT_FOUND' }
              }
            }
          }
        }
      },

      RateLimit: {
        description: 'Rate limit exceeded',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Rate limit exceeded' },
                retryAfter: { type: 'integer', example: 900 },
                code: { type: 'string', example: 'RATE_LIMIT_EXCEEDED' }
              }
            }
          }
        }
      },

      ServerError: {
        description: 'Internal server error',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                message: { type: 'string', example: 'Internal server error' },
                code: { type: 'string', example: 'INTERNAL_ERROR' },
                requestId: { type: 'string' }
              }
            }
          }
        }
      }
    },

    // Common data models
    schemas: {
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid', example: '123e4567-e89b-12d3-a456-426614174000' },
          email: { type: 'string', format: 'email', example: 'user@example.com' },
          username: { type: 'string', example: 'johndoe' },
          firstName: { type: 'string', example: 'John' },
          lastName: { type: 'string', example: 'Doe' },
          phone: { type: 'string', example: '+1234567890', nullable: true },
          status: { 
            type: 'string', 
            enum: ['active', 'inactive', 'suspended', 'pending_verification'],
            example: 'active'
          },
          emailVerified: { type: 'boolean', example: true },
          twoFactorEnabled: { type: 'boolean', example: false },
          lastLogin: { type: 'string', format: 'date-time', nullable: true },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' }
        },
        required: ['id', 'email', 'username', 'firstName', 'lastName']
      },

      Role: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'admin' },
          description: { type: 'string', example: 'System administrator with full access' },
          isSystemRole: { type: 'boolean', example: true },
          permissions: {
            type: 'array',
            items: { $ref: '#/components/schemas/Permission' }
          },
          createdAt: { type: 'string', format: 'date-time' }
        }
      },

      Permission: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'users:read' },
          description: { type: 'string', example: 'View user information' },
          resource: { type: 'string', example: 'users' },
          action: { type: 'string', example: 'read' },
          createdAt: { type: 'string', format: 'date-time' }
        }
      },

      JWTTokens: {
        type: 'object',
        properties: {
          accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
          refreshToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
          expiresIn: { type: 'string', example: '15m' },
          tokenType: { type: 'string', example: 'Bearer' }
        }
      },

      TwoFactorSetup: {
        type: 'object',
        properties: {
          secret: { type: 'string', example: 'JBSWY3DPEHPK3PXP' },
          qrCode: { type: 'string', example: 'data:image/png;base64,iVBORw0KGgo...' },
          backupCodes: {
            type: 'array',
            items: { type: 'string' },
            example: ['123456', '789012', '345678']
          },
          manualEntryKey: { type: 'string', example: 'JBSW Y3DP EHPK 3PXP' }
        }
      }
    },

    // Global parameters
    parameters: {
      PageParam: {
        name: 'page',
        in: 'query',
        description: 'Page number for pagination',
        schema: { type: 'integer', minimum: 1, default: 1 }
      },
      LimitParam: {
        name: 'limit',
        in: 'query',
        description: 'Number of items per page',
        schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 }
      },
      SortParam: {
        name: 'sort',
        in: 'query',
        description: 'Sort field and direction (e.g., "createdAt:desc")',
        schema: { type: 'string', example: 'createdAt:desc' }
      }
    }
  },

  // Global security requirement (can be overridden per endpoint)
  security: [
    { BearerAuth: [] }
  ],

  // API tags for organization
  tags: [
    {
      name: 'Authentication',
      description: `
## 🔐 Authentication Endpoints

Handle user authentication, registration, and session management.

### Features:
- User registration with email verification
- Secure login with JWT tokens
- Two-factor authentication (2FA)
- Password reset functionality
- Session management
      `,
      externalDocs: {
        description: 'Authentication Guide',
        url: 'https://docs.ufcauth.com/auth'
      }
    },
    {
      name: 'User Management',
      description: `
## 👥 User Management

Manage user profiles, status, and account information.

### Admin Features:
- List all users with filtering
- Update user status
- Assign/remove roles
- View user audit logs
      `
    },
    {
      name: 'RBAC',
      description: `
## 🛡️ Role-Based Access Control

Manage roles, permissions, and access control.

### Features:
- Dynamic role creation
- Granular permissions
- Role inheritance
- Permission validation
      `
    },
    {
      name: 'Audit',
      description: `
## 📊 Audit & Monitoring

Security audit trails and system monitoring.

### Features:
- Complete audit logging
- Security analytics
- Export capabilities
- Real-time monitoring
      `
    },
    {
      name: 'System',
      description: `
## ⚙️ System Information

Health checks, status, and system information.

### Monitoring:
- Health endpoints
- Performance metrics
- System status
- Database connectivity
      `
    }
  ],

  // External documentation links
  externalDocs: {
    description: 'Complete Documentation',
    url: 'https://docs.ufcauth.com'
  }
};

// Swagger JSDoc configuration
const swaggerOptions = {
  definition: swaggerDefinition,
  apis: [
    './src/routes/*.js',           // Main route files
    './src/controllers/*.js',      // Controller files for additional docs
    './src/schemas/*.js',          // Schema definitions
    './src/models/*.js'            // Model definitions
  ],
  // Swagger JSDoc options
  swaggerDefinition: {
    ...swaggerDefinition
  }
};

// Generate OpenAPI specification
export const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Swagger UI options following 2025 best practices
export const swaggerUIOptions = {
  // Core display options
  explorer: true,                    // Enable API explorer
  swaggerOptions: {
    // Authentication persistence
    persistAuthorization: true,     // Remember auth tokens
    
    // UI customization
    displayRequestDuration: true,   // Show request timing
    docExpansion: 'list',          // Expand operations list
    filter: true,                  // Enable search filter
    showExtensions: true,          // Show vendor extensions
    showCommonExtensions: true,    // Show common extensions
    
    // Request/Response display
    defaultModelsExpandDepth: 2,   // Expand models depth
    defaultModelExpandDepth: 2,    // Model expansion depth
    defaultModelRendering: 'example', // Show examples first
    
    // Try it out features
    tryItOutEnabled: true,         // Enable "Try it out"
    requestInterceptor: `(request) => {
      // Add custom headers or modify requests
      request.headers['X-Client'] = 'SwaggerUI';
      return request;
    }`,
    
    // Response interceptor for debugging
    responseInterceptor: `(response) => {
      // Log responses or handle errors
      console.log('API Response:', response.status, response.url);
      return response;
    }`,
    
    // Advanced features
    supportedSubmitMethods: ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'],
    validatorUrl: null,            // Disable spec validator
    oauth2RedirectUrl: '/api-docs/oauth2-redirect.html'
  },
  
  // Custom CSS styling
  customCss: `
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info .title { color: #1f2937; font-size: 2.5rem; }
    .swagger-ui .info .description { font-size: 1.1rem; line-height: 1.6; }
    .swagger-ui .scheme-container { background: #f8fafc; padding: 20px; border-radius: 8px; }
    .swagger-ui .auth-wrapper { margin-top: 20px; }
    .swagger-ui .btn.authorize { background-color: #3b82f6; border-color: #3b82f6; }
    .swagger-ui .btn.authorize:hover { background-color: #2563eb; }
    .swagger-ui .opblock.opblock-post { border-color: #10b981; }
    .swagger-ui .opblock.opblock-post .opblock-summary { border-color: #10b981; }
    .swagger-ui .opblock.opblock-get { border-color: #3b82f6; }
    .swagger-ui .opblock.opblock-get .opblock-summary { border-color: #3b82f6; }
    .swagger-ui .opblock.opblock-put { border-color: #f59e0b; }
    .swagger-ui .opblock.opblock-put .opblock-summary { border-color: #f59e0b; }
    .swagger-ui .opblock.opblock-delete { border-color: #ef4444; }
    .swagger-ui .opblock.opblock-delete .opblock-summary { border-color: #ef4444; }
  `,
  
  // Custom site title and favicon
  customSiteTitle: "UFC Auth API Documentation",
  customfavIcon: "/assets/favicon.ico",
  
  // Additional custom HTML for header
  customJs: [
    '/assets/swagger-custom.js'  // Custom JavaScript enhancements
  ]
};

export default { swaggerSpec, swaggerUIOptions }; 
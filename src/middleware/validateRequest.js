import Joi from 'joi';
import { ValidationError } from './errorHandler.js';
import { logger } from '../utils/logger.js';

/**
 * Common validation schemas
 */
export const commonSchemas = {
  // UUID validation
  uuid: Joi.string().uuid({ version: 'uuidv4' }).required(),
  
  // Email validation
  email: Joi.string().email().lowercase().trim().required(),
  
  // Password validation (strong password requirements)
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
    }),
  
  // Optional password for updates
  passwordOptional: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .optional()
    .messages({
      'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
    }),
  
  // Name validation
  name: Joi.string().trim().min(1).max(100).required(),
  
  // Optional name
  nameOptional: Joi.string().trim().min(1).max(100).optional(),
  
  // Phone number validation
  phone: Joi.string()
    .pattern(/^\+?[1-9]\d{1,14}$/)
    .optional()
    .messages({
      'string.pattern.base': 'Phone number must be in international format'
    }),
  
  // Date validation
  date: Joi.date().iso().required(),
  
  // Optional date
  dateOptional: Joi.date().iso().optional(),
  
  // Pagination
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(10),
  
  // Search query
  search: Joi.string().trim().min(1).max(100).optional(),
  
  // Sort options
  sortBy: Joi.string().valid('createdAt', 'updatedAt', 'name', 'email').default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  
  // Boolean
  boolean: Joi.boolean().optional(),
  
  // Array of UUIDs
  uuidArray: Joi.array().items(Joi.string().uuid({ version: 'uuidv4' })).optional(),
  
  // Role validation
  role: Joi.string().valid('admin', 'user', 'moderator').required(),
  
  // Permission validation
  permission: Joi.string().valid('read', 'write', 'delete', 'admin').required(),
  
  // Status validation
  status: Joi.string().valid('active', 'inactive', 'pending', 'suspended').optional(),
  
  // URL validation
  url: Joi.string().uri().optional(),
  
  // IP address validation
  ip: Joi.string().ip().optional(),
  
  // JWT token validation
  token: Joi.string().pattern(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/).required(),
  
  // OTP validation
  otp: Joi.string().length(6).pattern(/^\d{6}$/).required(),
  
  // TOTP secret validation
  totpSecret: Joi.string().length(32).pattern(/^[A-Z2-7]+$/).optional()
};

/**
 * Validation options
 */
const validationOptions = {
  abortEarly: false, // Return all validation errors
  allowUnknown: false, // Don't allow unknown fields
  stripUnknown: true, // Remove unknown fields
  convert: true, // Convert types when possible
  presence: 'required' // Default presence
};

/**
 * Create validation middleware
 */
export const validateRequest = (schema) => {
  return (req, res, next) => {
    const validationSchema = Joi.object(schema);
    
    // Combine all request data
    const requestData = {
      ...req.body,
      ...req.params,
      ...req.query
    };
    
    // Validate request data
    const { error, value } = validationSchema.validate(requestData, validationOptions);
    
    if (error) {
      // Log validation error
      logger.logSecurity('VALIDATION_ERROR', req, {
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }))
      });
      
      // Create validation error with first error message
      const firstError = error.details[0];
      const validationError = new ValidationError(
        firstError.message,
        firstError.path.join('.')
      );
      
      return next(validationError);
    }
    
    // Replace request data with validated and sanitized data
    Object.keys(req.body).forEach(key => {
      if (value[key] !== undefined) {
        req.body[key] = value[key];
      }
    });
    
    Object.keys(req.params).forEach(key => {
      if (value[key] !== undefined) {
        req.params[key] = value[key];
      }
    });
    
    Object.keys(req.query).forEach(key => {
      if (value[key] !== undefined) {
        req.query[key] = value[key];
      }
    });
    
    // Add validated data to request
    req.validated = value;
    
    next();
  };
};

/**
 * Validate specific parts of request
 */
export const validateBody = (schema) => {
  return (req, res, next) => {
    const validationSchema = Joi.object(schema);
    const { error, value } = validationSchema.validate(req.body, validationOptions);
    
    if (error) {
      logger.logSecurity('BODY_VALIDATION_ERROR', req, {
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      });
      
      const firstError = error.details[0];
      return next(new ValidationError(firstError.message, firstError.path.join('.')));
    }
    
    req.body = value;
    next();
  };
};

export const validateParams = (schema) => {
  return (req, res, next) => {
    const validationSchema = Joi.object(schema);
    const { error, value } = validationSchema.validate(req.params, validationOptions);
    
    if (error) {
      logger.logSecurity('PARAMS_VALIDATION_ERROR', req, {
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      });
      
      const firstError = error.details[0];
      return next(new ValidationError(firstError.message, firstError.path.join('.')));
    }
    
    req.params = value;
    next();
  };
};

export const validateQuery = (schema) => {
  return (req, res, next) => {
    const validationSchema = Joi.object(schema);
    const { error, value } = validationSchema.validate(req.query, validationOptions);
    
    if (error) {
      logger.logSecurity('QUERY_VALIDATION_ERROR', req, {
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      });
      
      const firstError = error.details[0];
      return next(new ValidationError(firstError.message, firstError.path.join('.')));
    }
    
    req.query = value;
    next();
  };
};

/**
 * Common validation schemas for routes
 */
export const validationSchemas = {
  // User registration
  register: {
    firstName: commonSchemas.name,
    lastName: commonSchemas.name,
    email: commonSchemas.email,
    password: commonSchemas.password,
    phone: commonSchemas.phone
  },
  
  // User login
  login: {
    email: commonSchemas.email,
    password: Joi.string().required(),
    rememberMe: commonSchemas.boolean
  },
  
  // Password reset request
  forgotPassword: {
    email: commonSchemas.email
  },
  
  // Password reset
  resetPassword: {
    token: commonSchemas.token,
    password: commonSchemas.password
  },
  
  // Change password
  changePassword: {
    currentPassword: Joi.string().required(),
    newPassword: commonSchemas.password
  },
  
  // Update profile
  updateProfile: {
    firstName: commonSchemas.nameOptional,
    lastName: commonSchemas.nameOptional,
    phone: commonSchemas.phone
  },
  
  // User ID parameter
  userId: {
    id: commonSchemas.uuid
  },
  
  // Pagination query
  pagination: {
    page: commonSchemas.page,
    limit: commonSchemas.limit,
    search: commonSchemas.search,
    sortBy: commonSchemas.sortBy,
    sortOrder: commonSchemas.sortOrder
  },
  
  // 2FA setup
  setup2FA: {
    secret: commonSchemas.totpSecret,
    token: commonSchemas.otp
  },
  
  // 2FA verification
  verify2FA: {
    token: commonSchemas.otp
  },
  
  // Role assignment
  assignRole: {
    userId: commonSchemas.uuid,
    roleId: commonSchemas.uuid
  }
};

export default validateRequest; 
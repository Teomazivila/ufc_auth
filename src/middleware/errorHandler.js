import { logger } from '../utils/logger.js';
import { config } from '../config/index.js';

/**
 * Custom error classes
 */
export class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', isOperational = true) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message, field = null) {
    super(message, 400, 'VALIDATION_ERROR');
    this.field = field;
  }
}

export class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND_ERROR');
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409, 'CONFLICT_ERROR');
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Too many requests') {
    super(message, 429, 'RATE_LIMIT_ERROR');
  }
}

export class DatabaseError extends AppError {
  constructor(message = 'Database operation failed') {
    super(message, 500, 'DATABASE_ERROR');
  }
}

export class ExternalServiceError extends AppError {
  constructor(message = 'External service unavailable') {
    super(message, 503, 'EXTERNAL_SERVICE_ERROR');
  }
}

/**
 * Error response formatter
 */
const formatErrorResponse = (error, req) => {
  const isDevelopment = config.nodeEnv === 'development';
  const isProduction = config.nodeEnv === 'production';

  const baseResponse = {
    success: false,
    error: {
      code: error.code || 'INTERNAL_ERROR',
      message: error.message,
      timestamp: error.timestamp || new Date().toISOString(),
      requestId: req.id || req.headers['x-request-id']
    }
  };

  // Add field information for validation errors
  if (error instanceof ValidationError && error.field) {
    baseResponse.error.field = error.field;
  }

  // Add stack trace in development
  if (isDevelopment && error.stack) {
    baseResponse.error.stack = error.stack;
  }

  // Add additional debug info in development
  if (isDevelopment) {
    baseResponse.error.details = {
      name: error.name,
      statusCode: error.statusCode,
      isOperational: error.isOperational
    };
  }

  // Sanitize error message in production for security
  if (isProduction && !error.isOperational) {
    baseResponse.error.message = 'Internal server error';
  }

  return baseResponse;
};

/**
 * Handle specific error types
 */
const handleDatabaseError = (error) => {
  // PostgreSQL specific errors
  if (error.code) {
    switch (error.code) {
      case '23505': // unique_violation
        return new ConflictError('Resource already exists');
      case '23503': // foreign_key_violation
        return new ValidationError('Referenced resource does not exist');
      case '23502': // not_null_violation
        return new ValidationError('Required field is missing');
      case '23514': // check_violation
        return new ValidationError('Invalid field value');
      case '42P01': // undefined_table
        return new DatabaseError('Database table not found');
      case '42703': // undefined_column
        return new DatabaseError('Database column not found');
      case '28P01': // invalid_password
        return new DatabaseError('Database authentication failed');
      case '3D000': // invalid_catalog_name
        return new DatabaseError('Database does not exist');
      default:
        return new DatabaseError(`Database error: ${error.message}`);
    }
  }

  return new DatabaseError('Database operation failed');
};

const handleJWTError = (error) => {
  if (error.name === 'JsonWebTokenError') {
    return new AuthenticationError('Invalid token');
  }
  if (error.name === 'TokenExpiredError') {
    return new AuthenticationError('Token expired');
  }
  if (error.name === 'NotBeforeError') {
    return new AuthenticationError('Token not active');
  }
  return new AuthenticationError('Token validation failed');
};

const handleValidationError = (error) => {
  // Handle Joi validation errors
  if (error.isJoi) {
    const message = error.details[0]?.message || 'Validation failed';
    const field = error.details[0]?.path?.join('.') || null;
    return new ValidationError(message, field);
  }

  // Handle express-validator errors
  if (error.array && typeof error.array === 'function') {
    const errors = error.array();
    if (errors.length > 0) {
      const firstError = errors[0];
      return new ValidationError(firstError.msg, firstError.param);
    }
  }

  return new ValidationError('Validation failed');
};

const handleMulterError = (error) => {
  switch (error.code) {
    case 'LIMIT_FILE_SIZE':
      return new ValidationError('File too large');
    case 'LIMIT_FILE_COUNT':
      return new ValidationError('Too many files');
    case 'LIMIT_UNEXPECTED_FILE':
      return new ValidationError('Unexpected file field');
    case 'LIMIT_PART_COUNT':
      return new ValidationError('Too many parts');
    case 'LIMIT_FIELD_KEY':
      return new ValidationError('Field name too long');
    case 'LIMIT_FIELD_VALUE':
      return new ValidationError('Field value too long');
    case 'LIMIT_FIELD_COUNT':
      return new ValidationError('Too many fields');
    default:
      return new ValidationError('File upload error');
  }
};

/**
 * Main error handling middleware
 */
export const errorHandler = (error, req, res, next) => {
  let processedError = error;

  // Convert known error types to AppError instances
  if (!(error instanceof AppError)) {
    // Database errors
    if (error.code && typeof error.code === 'string') {
      processedError = handleDatabaseError(error);
    }
    // JWT errors
    else if (error.name && error.name.includes('Token')) {
      processedError = handleJWTError(error);
    }
    // Validation errors
    else if (error.isJoi || (error.array && typeof error.array === 'function')) {
      processedError = handleValidationError(error);
    }
    // Multer errors
    else if (error.code && error.code.startsWith('LIMIT_')) {
      processedError = handleMulterError(error);
    }
    // Syntax errors
    else if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
      processedError = new ValidationError('Invalid JSON in request body');
    }
    // Cast to generic AppError
    else {
      processedError = new AppError(
        error.message || 'Internal server error',
        error.statusCode || 500,
        error.code || 'INTERNAL_ERROR',
        false
      );
    }
  }

  // Log error with appropriate level
  if (processedError.statusCode >= 500) {
    logger.logError(processedError, req, {
      originalError: error !== processedError ? error.message : undefined
    });
  } else if (processedError.statusCode >= 400) {
    logger.logSecurity('CLIENT_ERROR', req, {
      error: processedError.message,
      code: processedError.code,
      statusCode: processedError.statusCode
    });
  }

  // Format and send error response
  const errorResponse = formatErrorResponse(processedError, req);
  
  res.status(processedError.statusCode).json(errorResponse);
};

/**
 * Async error wrapper
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Promise Rejection:', {
    reason: reason?.message || reason,
    stack: reason?.stack,
    promise: promise.toString()
  });
  
  // In production, gracefully shutdown
  if (config.nodeEnv === 'production') {
    process.exit(1);
  }
});

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', {
    message: error.message,
    stack: error.stack,
    name: error.name
  });
  
  // Always exit on uncaught exception
  process.exit(1);
});

export default errorHandler; 
import { logger } from '../utils/logger.js';
import { config } from '../config/index.js';

/**
 * Custom Error Classes
 * Following 2025 best practices for Node.js 20+ error handling
 */

export class AppError extends Error {
  constructor(message, statusCode, code = null, details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      statusCode: this.statusCode,
      code: this.code,
      details: this.details,
      timestamp: this.timestamp,
      ...(config.nodeEnv === 'development' && { stack: this.stack })
    };
  }
}

export class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized', code = 'UNAUTHORIZED') {
    super(message, 401, code);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', code = 'FORBIDDEN') {
    super(message, 403, code);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
  }
}

export class ConflictError extends AppError {
  constructor(message, details = null) {
    super(message, 409, 'CONFLICT', details);
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message = 'Too many requests', retryAfter = null) {
    super(message, 429, 'TOO_MANY_REQUESTS');
    this.retryAfter = retryAfter;
  }
}

export class InternalServerError extends AppError {
  constructor(message = 'Internal server error') {
    super(message, 500, 'INTERNAL_SERVER_ERROR');
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message = 'Service unavailable') {
    super(message, 503, 'SERVICE_UNAVAILABLE');
  }
}

/**
 * Async handler wrapper to catch async errors
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Sanitize error for production
 */
const sanitizeError = (error) => {
  // In production, don't expose internal error details
  if (config.nodeEnv === 'production' && !error.isOperational) {
    return {
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Something went wrong. Please try again later.',
        timestamp: new Date().toISOString()
      }
    };
  }

  return {
    success: false,
    error: error.toJSON ? error.toJSON() : {
      code: error.code || 'UNKNOWN_ERROR',
      message: error.message || 'An unexpected error occurred',
      timestamp: new Date().toISOString(),
      ...(config.nodeEnv === 'development' && { 
        stack: error.stack,
        details: error.details 
      })
    }
  };
};

/**
 * Handle specific error types
 */
const handleDatabaseError = (error) => {
  logger.error('Database error:', error);

  // PostgreSQL specific errors
  if (error.code === '23505') { // Unique violation
    const field = error.detail?.match(/Key \((.+)\)=/)?.[1] || 'field';
    return new ConflictError(`${field} already exists`);
  }

  if (error.code === '23503') { // Foreign key violation
    return new ValidationError('Referenced resource does not exist');
  }

  if (error.code === '23502') { // Not null violation
    const field = error.column || 'field';
    return new ValidationError(`${field} is required`);
  }

  if (error.code === '22001') { // String data too long
    return new ValidationError('Input data is too long');
  }

  // Connection errors
  if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
    return new ServiceUnavailableError('Database connection failed');
  }

  return new InternalServerError('Database operation failed');
};

/**
 * Handle Redis errors
 */
const handleRedisError = (error) => {
  logger.error('Redis error:', error);

  if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
    return new ServiceUnavailableError('Cache service unavailable');
  }

  return new InternalServerError('Cache operation failed');
};

/**
 * Handle JWT errors
 */
const handleJWTError = (error) => {
  if (error.name === 'JsonWebTokenError') {
    return new UnauthorizedError('Invalid token');
  }

  if (error.name === 'TokenExpiredError') {
    return new UnauthorizedError('Token expired');
  }

  if (error.name === 'NotBeforeError') {
    return new UnauthorizedError('Token not active');
  }

  return new UnauthorizedError('Token verification failed');
};

/**
 * Handle validation errors (Joi)
 */
const handleValidationError = (error) => {
  if (error.isJoi) {
    const details = error.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message,
      value: detail.context?.value
    }));

    return new ValidationError('Validation failed', details);
  }

  return error;
};

/**
 * Main error handler middleware
 */
export const errorHandler = (error, req, res, next) => {
  // Skip if response already sent
  if (res.headersSent) {
    return next(error);
  }

  let processedError = error;

  // Handle specific error types
  if (error.name?.includes('Sequelize') || error.code?.startsWith('23')) {
    processedError = handleDatabaseError(error);
  } else if (error.name?.includes('Redis') || error.code === 'ECONNREFUSED') {
    processedError = handleRedisError(error);
  } else if (error.name?.includes('JsonWebToken') || error.name?.includes('Token')) {
    processedError = handleJWTError(error);
  } else if (error.isJoi) {
    processedError = handleValidationError(error);
  } else if (!(error instanceof AppError)) {
    // Convert unknown errors to AppError
    processedError = new InternalServerError(error.message);
  }

  // Log error with context
  const logContext = {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    error: {
      name: processedError.name,
      message: processedError.message,
      code: processedError.code,
      statusCode: processedError.statusCode,
      stack: processedError.stack
    }
  };

  // Log based on severity
  if (processedError.statusCode >= 500) {
    logger.error('Server error:', logContext);
  } else if (processedError.statusCode >= 400) {
    logger.warn('Client error:', logContext);
  } else {
    logger.info('Request error:', logContext);
  }

  // Set security headers for error responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  // Handle rate limiting headers
  if (processedError instanceof TooManyRequestsError && processedError.retryAfter) {
    res.setHeader('Retry-After', processedError.retryAfter);
  }

  // Send error response
  const statusCode = processedError.statusCode || 500;
  const errorResponse = sanitizeError(processedError);

  res.status(statusCode).json(errorResponse);
};

/**
 * Handle 404 errors for undefined routes
 */
export const notFoundHandler = (req, res, next) => {
  const error = new NotFoundError(`Route ${req.method} ${req.originalUrl} not found`);
  
  logger.warn('Route not found:', {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  next(error);
};

/**
 * Handle uncaught exceptions
 */
export const handleUncaughtException = (error) => {
  logger.error('Uncaught Exception:', error);
  
  // Graceful shutdown
  process.exit(1);
};

/**
 * Handle unhandled promise rejections
 */
export const handleUnhandledRejection = (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  
  // Graceful shutdown
  process.exit(1);
};

export default {
  AppError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  TooManyRequestsError,
  InternalServerError,
  ServiceUnavailableError,
  asyncHandler,
  errorHandler,
  notFoundHandler,
  handleUncaughtException,
  handleUnhandledRejection
}; 
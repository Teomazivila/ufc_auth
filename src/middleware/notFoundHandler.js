import { NotFoundError } from './errorHandler.js';
import { logger } from '../utils/logger.js';

/**
 * 404 Not Found handler middleware
 * This should be the last middleware before the error handler
 */
export const notFoundHandler = (req, res, next) => {
  // Log the 404 attempt for security monitoring
  logger.logSecurity('ROUTE_NOT_FOUND', req, {
    path: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer') || null
  });

  // Create a not found error
  const error = new NotFoundError(`Route ${req.method} ${req.originalUrl} not found`);
  
  // Pass to error handler
  next(error);
};

export default notFoundHandler; 
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger.js';
import { config } from '../config/index.js';

/**
 * Request logging middleware
 * Adds request ID and logs request details
 */
export const requestLogger = (req, res, next) => {
  // Generate unique request ID
  req.id = req.headers['x-request-id'] || uuidv4();
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', req.id);
  
  // Capture start time for response time calculation
  const startTime = Date.now();
  
  // Log request start
  logger.info('Request started', {
    requestId: req.id,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer') || null,
    contentType: req.get('Content-Type') || null,
    contentLength: req.get('Content-Length') || null,
    userId: req.user?.id || null,
    timestamp: new Date().toISOString()
  });
  
  // Capture original res.end to log response
  const originalEnd = res.end;
  
  res.end = function(chunk, encoding) {
    // Calculate response time
    const responseTime = Date.now() - startTime;
    
    // Log response
    logger.logRequest(req, res, responseTime);
    
    // Log additional response details
    logger.info('Request completed', {
      requestId: req.id,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      contentLength: res.get('Content-Length') || null,
      userId: req.user?.id || null,
      timestamp: new Date().toISOString()
    });
    
    // Call original end method
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

/**
 * Enhanced request logger with body logging (for development)
 */
export const detailedRequestLogger = (req, res, next) => {
  // Only log detailed info in development
  if (config.app.env !== 'development') {
    return requestLogger(req, res, next);
  }
  
  // Generate unique request ID
  req.id = req.headers['x-request-id'] || uuidv4();
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', req.id);
  
  // Capture start time
  const startTime = Date.now();
  
  // Sanitize sensitive data from body
  const sanitizeBody = (body) => {
    if (!body || typeof body !== 'object') return body;
    
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
    const sanitized = { ...body };
    
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }
    
    return sanitized;
  };
  
  // Log detailed request
  logger.debug('Detailed request', {
    requestId: req.id,
    method: req.method,
    url: req.originalUrl,
    headers: {
      ...req.headers,
      authorization: req.headers.authorization ? '[REDACTED]' : undefined,
      cookie: req.headers.cookie ? '[REDACTED]' : undefined
    },
    params: req.params,
    query: req.query,
    body: sanitizeBody(req.body),
    ip: req.ip || req.connection.remoteAddress,
    timestamp: new Date().toISOString()
  });
  
  // Capture original res.json to log response body
  const originalJson = res.json;
  const originalEnd = res.end;
  
  res.json = function(body) {
    // Log response body in development
    logger.debug('Response body', {
      requestId: req.id,
      statusCode: res.statusCode,
      body: body
    });
    
    return originalJson.call(this, body);
  };
  
  res.end = function(chunk, encoding) {
    const responseTime = Date.now() - startTime;
    
    logger.debug('Request completed (detailed)', {
      requestId: req.id,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      headers: res.getHeaders(),
      timestamp: new Date().toISOString()
    });
    
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

export default requestLogger; 
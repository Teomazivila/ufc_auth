import jwt from 'jsonwebtoken';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { User } from '../models/User.js';
import { getRedisClient } from '../config/redis.js';
import { 
  UnauthorizedError, 
  ForbiddenError, 
  TooManyRequestsError 
} from './errorHandler.js';

/**
 * Authentication Middleware
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Extract JWT token from request headers
 */
const extractToken = (req) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return null;
  }

  // Support both "Bearer token" and "token" formats
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  return authHeader;
};

/**
 * Verify JWT access token
 */
export const authenticateToken = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      throw new UnauthorizedError('Access token required');
    }

    // Verify token
    const decoded = jwt.verify(token, config.jwt.secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    });

    // Ensure it's an access token
    if (decoded.type !== 'access') {
      throw new UnauthorizedError('Invalid token type');
    }

    // Check if token is blacklisted
    const blacklistKey = `blacklist:${token}`;
    const isBlacklisted = await getRedisClient().exists(blacklistKey);
    
    if (isBlacklisted) {
      throw new UnauthorizedError('Token has been revoked');
    }

    // Get user from database
    const user = await User.findById(decoded.id);
    
    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    if (user.status !== 'active') {
      throw new UnauthorizedError('Account is not active');
    }

    if (user.isLocked()) {
      throw new UnauthorizedError('Account is temporarily locked');
    }

    // Attach user to request
    req.user = user;
    req.token = token;
    req.tokenPayload = decoded;

    logger.debug('User authenticated successfully', { 
      userId: user.id, 
      email: user.email,
      requestId: req.requestId 
    });

    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      logger.warn('Invalid JWT token', { 
        error: error.message,
        requestId: req.requestId,
        ip: req.ip 
      });
      return next(new UnauthorizedError('Invalid access token'));
    }
    
    if (error.name === 'TokenExpiredError') {
      logger.warn('Expired JWT token', { 
        requestId: req.requestId,
        ip: req.ip 
      });
      return next(new UnauthorizedError('Access token expired'));
    }

    logger.error('Authentication error:', error);
    next(error);
  }
};

/**
 * Optional authentication - doesn't fail if no token provided
 */
export const optionalAuth = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return next(); // Continue without authentication
    }

    // Try to authenticate, but don't fail if it doesn't work
    await authenticateToken(req, res, (error) => {
      if (error) {
        // Log the error but continue without authentication
        logger.debug('Optional authentication failed', { 
          error: error.message,
          requestId: req.requestId 
        });
      }
      next(); // Always continue
    });
  } catch (error) {
    // Log error but continue without authentication
    logger.debug('Optional authentication error', { 
      error: error.message,
      requestId: req.requestId 
    });
    next();
  }
};

/**
 * Require 2FA verification for sensitive operations
 */
export const require2FA = async (req, res, next) => {
  try {
    if (!req.user) {
      throw new UnauthorizedError('Authentication required');
    }

    // If user doesn't have 2FA enabled, allow access
    if (!req.user.two_factor_enabled) {
      return next();
    }

    // Check if 2FA was verified in this session
    const sessionKey = `2fa_verified:${req.user.id}:${req.tokenPayload.jti || 'session'}`;
    const isVerified = await getRedisClient().exists(sessionKey);

    if (!isVerified) {
      throw new ForbiddenError('2FA verification required', 'REQUIRE_2FA');
    }

    logger.debug('2FA verification confirmed', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    next();
  } catch (error) {
    logger.warn('2FA verification failed', { 
      userId: req.user?.id,
      error: error.message,
      requestId: req.requestId 
    });
    next(error);
  }
};

/**
 * Verify 2FA token and mark session as verified
 */
export const verify2FAToken = async (req, res, next) => {
  try {
    const { twoFactorToken, backupCode } = req.body;
    
    if (!req.user) {
      throw new UnauthorizedError('Authentication required');
    }

    if (!req.user.two_factor_enabled) {
      throw new ForbiddenError('2FA is not enabled for this account');
    }

    let verified = false;

    // Try 2FA token first
    if (twoFactorToken) {
      verified = await req.user.verify2FA(twoFactorToken);
    }
    
    // Try backup code if token failed
    if (!verified && backupCode) {
      verified = await req.user.useBackupCode(backupCode);
    }

    if (!verified) {
      throw new UnauthorizedError('Invalid 2FA token or backup code');
    }

    // Mark session as 2FA verified (expires in 30 minutes)
    const sessionKey = `2fa_verified:${req.user.id}:${req.tokenPayload.jti || 'session'}`;
    await getRedisClient().setEx(sessionKey, 1800, 'verified'); // 30 minutes

    logger.info('2FA verification successful', { 
      userId: req.user.id,
      method: twoFactorToken ? 'totp' : 'backup_code',
      requestId: req.requestId 
    });

    req.twoFactorVerified = true;
    next();
  } catch (error) {
    logger.warn('2FA token verification failed', { 
      userId: req.user?.id,
      error: error.message,
      requestId: req.requestId 
    });
    next(error);
  }
};

/**
 * Rate limiting for authentication endpoints
 */
export const authRateLimit = async (req, res, next) => {
  try {
    const identifier = req.ip;
    const key = `auth_rate_limit:${identifier}`;
    
    // Get current count
    const current = await getRedisClient().get(key);
    const count = current ? parseInt(current) : 0;

    // Allow 10 attempts per 15 minutes
    const limit = 10;
    const windowSeconds = 900; // 15 minutes

    if (count >= limit) {
      const ttl = await getRedisClient().ttl(key);
      
      logger.warn('Authentication rate limit exceeded', { 
        ip: req.ip,
        count,
        requestId: req.requestId 
      });
      
      throw new TooManyRequestsError(
        'Too many authentication attempts. Please try again later.',
        ttl > 0 ? ttl : windowSeconds
      );
    }

    // Increment counter
    if (count === 0) {
      await getRedisClient().setEx(key, windowSeconds, '1');
    } else {
      await getRedisClient().incr(key);
    }

    next();
  } catch (error) {
    if (error instanceof TooManyRequestsError) {
      return next(error);
    }
    
    logger.error('Auth rate limit error:', error);
    next(); // Continue on Redis errors
  }
};

/**
 * Blacklist token (for logout)
 */
export const blacklistToken = async (token, expiresIn = null) => {
  try {
    const decoded = jwt.decode(token);
    const blacklistKey = `blacklist:${token}`;
    
    // Calculate expiration time
    let ttl = expiresIn;
    if (!ttl && decoded?.exp) {
      ttl = decoded.exp - Math.floor(Date.now() / 1000);
    }
    
    if (ttl > 0) {
      await getRedisClient().setEx(blacklistKey, ttl, 'blacklisted');
      logger.info('Token blacklisted', { 
        tokenId: decoded?.jti,
        userId: decoded?.id,
        ttl 
      });
    }
  } catch (error) {
    logger.error('Error blacklisting token:', error);
    throw error;
  }
};

/**
 * Require account verification
 */
export const requireVerification = (req, res, next) => {
  try {
    if (!req.user) {
      throw new UnauthorizedError('Authentication required');
    }

    if (!req.user.email_verified) {
      throw new ForbiddenError('Account verification required', 'REQUIRE_VERIFICATION');
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check if user has specific role
 */
export const requireRole = (roles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      // Get user roles from database (will be implemented in Week 3)
      // For now, assume admin role for user ID 1
      const userRoles = req.user.id === 1 ? ['admin'] : ['user'];
      
      const hasRole = Array.isArray(roles) 
        ? roles.some(role => userRoles.includes(role))
        : userRoles.includes(roles);

      if (!hasRole) {
        throw new ForbiddenError('Insufficient permissions');
      }

      req.userRoles = userRoles;
      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Security headers middleware
 */
export const securityHeaders = (req, res, next) => {
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Remove server information
  res.removeHeader('X-Powered-By');
  
  next();
};

export default {
  authenticateToken,
  optionalAuth,
  require2FA,
  verify2FAToken,
  authRateLimit,
  blacklistToken,
  requireVerification,
  requireRole,
  securityHeaders
}; 
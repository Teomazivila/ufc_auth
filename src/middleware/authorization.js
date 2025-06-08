import { User } from '../models/User.js';
import { logger } from '../utils/logger.js';

/**
 * Authorization Middleware for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Check if user has required permission
 */
export const requirePermission = (permissionName) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      const hasPermission = await user.hasPermission(permissionName);
      if (!hasPermission) {
        logger.warn('Permission denied', {
          userId: user.id,
          email: user.email,
          requiredPermission: permissionName,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions',
          required_permission: permissionName
        });
      }

      // Add user permissions to request for further use
      req.userPermissions = await user.getPermissions();
      next();
    } catch (error) {
      logger.error('Error in permission check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Check if user has required role
 */
export const requireRole = (roleName) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      const hasRole = await user.hasRole(roleName);
      if (!hasRole) {
        logger.warn('Role access denied', {
          userId: user.id,
          email: user.email,
          requiredRole: roleName,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient role privileges',
          required_role: roleName
        });
      }

      // Add user roles to request for further use
      req.userRoles = await user.getRoles();
      next();
    } catch (error) {
      logger.error('Error in role check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Check if user has any of the required permissions
 */
export const requireAnyPermission = (permissionNames) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      let hasAnyPermission = false;
      for (const permission of permissionNames) {
        if (await user.hasPermission(permission)) {
          hasAnyPermission = true;
          break;
        }
      }

      if (!hasAnyPermission) {
        logger.warn('Permission denied - none of required permissions found', {
          userId: user.id,
          email: user.email,
          requiredPermissions: permissionNames,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions',
          required_permissions: permissionNames
        });
      }

      // Add user permissions to request for further use
      req.userPermissions = await user.getPermissions();
      next();
    } catch (error) {
      logger.error('Error in any permission check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Check if user has any of the required roles
 */
export const requireAnyRole = (roleNames) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      let hasAnyRole = false;
      for (const role of roleNames) {
        if (await user.hasRole(role)) {
          hasAnyRole = true;
          break;
        }
      }

      if (!hasAnyRole) {
        logger.warn('Role access denied - none of required roles found', {
          userId: user.id,
          email: user.email,
          requiredRoles: roleNames,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient role privileges',
          required_roles: roleNames
        });
      }

      // Add user roles to request for further use
      req.userRoles = await user.getRoles();
      next();
    } catch (error) {
      logger.error('Error in any role check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Check if user can perform specific action on resource
 */
export const requireResourceAction = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      const canPerform = await user.canPerform(resource, action);
      if (!canPerform) {
        logger.warn('Resource action denied', {
          userId: user.id,
          email: user.email,
          resource,
          action,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions for this action',
          required_resource: resource,
          required_action: action
        });
      }

      next();
    } catch (error) {
      logger.error('Error in resource action check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Check if user is admin (has admin role)
 */
export const requireAdmin = requireRole('admin');

/**
 * Check if user is moderator or admin
 */
export const requireModerator = requireAnyRole(['admin', 'moderator']);

/**
 * Check if user can access their own resource or is admin
 */
export const requireOwnershipOrAdmin = (userIdParam = 'userId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const targetUserId = req.params[userIdParam];
      const currentUserId = req.user.id;

      // Allow if user is accessing their own resource
      if (targetUserId && targetUserId.toString() === currentUserId.toString()) {
        return next();
      }

      // Check if user is admin
      const user = await User.findById(currentUserId);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      const isAdmin = await user.hasRole('admin');
      if (!isAdmin) {
        logger.warn('Ownership or admin access denied', {
          userId: currentUserId,
          targetUserId,
          endpoint: req.originalUrl,
          method: req.method
        });

        return res.status(403).json({
          success: false,
          message: 'Access denied: insufficient privileges'
        });
      }

      next();
    } catch (error) {
      logger.error('Error in ownership or admin check:', error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error during authorization'
      });
    }
  };
};

/**
 * Load user permissions and roles into request
 */
export const loadUserPermissions = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return next();
    }

    // Load permissions and roles
    req.userPermissions = await user.getPermissions();
    req.userRoles = await user.getRoles();
    
    next();
  } catch (error) {
    logger.error('Error loading user permissions:', error);
    // Don't fail the request, just continue without permissions
    next();
  }
};

/**
 * Helper function to check permissions in controllers
 */
export const checkPermission = async (userId, permissionName) => {
  try {
    const user = await User.findById(userId);
    if (!user) return false;
    
    return await user.hasPermission(permissionName);
  } catch (error) {
    logger.error('Error checking permission:', error);
    return false;
  }
};

/**
 * Helper function to check roles in controllers
 */
export const checkRole = async (userId, roleName) => {
  try {
    const user = await User.findById(userId);
    if (!user) return false;
    
    return await user.hasRole(roleName);
  } catch (error) {
    logger.error('Error checking role:', error);
    return false;
  }
};

export default {
  requirePermission,
  requireRole,
  requireAnyPermission,
  requireAnyRole,
  requireResourceAction,
  requireAdmin,
  requireModerator,
  requireOwnershipOrAdmin,
  loadUserPermissions,
  checkPermission,
  checkRole
}; 
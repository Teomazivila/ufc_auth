import { User } from '../models/User.js';
import { Role } from '../models/Role.js';
import { logger } from '../utils/logger.js';
import { validationResult } from 'express-validator';
import { query } from '../config/database.js';

/**
 * User Management Controller for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Get all users with pagination and filtering
 */
export const getUsers = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      status = '',
      role = '',
      sortBy = 'created_at',
      sortOrder = 'desc'
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const limitNum = Math.min(parseInt(limit), 100); // Max 100 per page

    // Build dynamic WHERE clause
    let whereConditions = [];
    let queryParams = [];
    let paramIndex = 1;

    if (search) {
      whereConditions.push(`(u.email ILIKE $${paramIndex} OR u.username ILIKE $${paramIndex} OR u.first_name ILIKE $${paramIndex} OR u.last_name ILIKE $${paramIndex})`);
      queryParams.push(`%${search}%`);
      paramIndex++;
    }

    if (status) {
      whereConditions.push(`u.status = $${paramIndex}`);
      queryParams.push(status);
      paramIndex++;
    }

    if (role) {
      whereConditions.push(`r.name = $${paramIndex}`);
      queryParams.push(role);
      paramIndex++;
    }

    const whereClause = whereConditions.length > 0 
      ? `WHERE ${whereConditions.join(' AND ')}`
      : '';

    // Validate sort parameters
    const validSortFields = ['created_at', 'email', 'username', 'first_name', 'last_name', 'status', 'last_login'];
    const validSortOrders = ['asc', 'desc'];
    
    const sortField = validSortFields.includes(sortBy) ? sortBy : 'created_at';
    const sortDirection = validSortOrders.includes(sortOrder.toLowerCase()) ? sortOrder.toUpperCase() : 'DESC';

    const queryText = `
      SELECT DISTINCT u.id, u.email, u.username, u.first_name, u.last_name, 
             u.status, u.email_verified, u.last_login, u.login_attempts, 
             u.two_factor_enabled, u.created_at, u.updated_at,
             COALESCE(
               json_agg(
                 json_build_object(
                   'id', r.id,
                   'name', r.name,
                   'description', r.description,
                   'is_system_role', r.is_system_role
                 )
               ) FILTER (WHERE r.id IS NOT NULL), 
               '[]'
             ) as roles
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      ${whereClause}
      GROUP BY u.id
      ORDER BY u.${sortField} ${sortDirection}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    const countQuery = `
      SELECT COUNT(DISTINCT u.id) as total
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      ${whereClause}
    `;

    queryParams.push(limitNum, offset);

    const [usersResult, countResult] = await Promise.all([
      query(queryText, queryParams),
      query(countQuery, queryParams.slice(0, -2)) // Remove limit and offset for count
    ]);

    const total = parseInt(countResult.rows[0].total);

    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: {
        users: usersResult.rows,
        pagination: {
          page: parseInt(page),
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum)
        }
      }
    });
  } catch (error) {
    logger.error('Error getting users:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get user by ID with roles and permissions
 */
export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get user roles and permissions
    const [roles, permissions] = await Promise.all([
      user.getRoles(),
      user.getPermissions()
    ]);

    const userData = user.toSafeObject();
    userData.roles = roles;
    userData.permissions = permissions;

    res.json({
      success: true,
      message: 'User retrieved successfully',
      data: {
        user: userData
      }
    });
  } catch (error) {
    logger.error('Error getting user by ID:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Update user status
 */
export const updateUserStatus = async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body;

    const validStatuses = ['active', 'inactive', 'suspended'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be one of: active, inactive, suspended'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Prevent self-deactivation
    if (userId === req.user.id && status !== 'active') {
      return res.status(403).json({
        success: false,
        message: 'Cannot deactivate your own account'
      });
    }

    const queryText = `
      UPDATE users 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *
    `;

    const result = await query(queryText, [status, userId]);
    
    logger.info('User status updated', {
      userId,
      newStatus: status,
      updatedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'User status updated successfully',
      data: {
        user: {
          id: result.rows[0].id,
          email: result.rows[0].email,
          status: result.rows[0].status
        }
      }
    });
  } catch (error) {
    logger.error('Error updating user status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Assign role to user
 */
export const assignRoleToUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { roleId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    const assigned = await user.assignRole(roleId);
    
    if (!assigned) {
      return res.status(409).json({
        success: false,
        message: 'Role already assigned to user'
      });
    }

    logger.info('Role assigned to user', {
      userId: user.id,
      roleId: role.id,
      roleName: role.name,
      assignedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Role assigned to user successfully'
    });
  } catch (error) {
    logger.error('Error assigning role to user:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Remove role from user
 */
export const removeRoleFromUser = async (req, res) => {
  try {
    const { userId, roleId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const removed = await user.removeRole(roleId);
    
    if (!removed) {
      return res.status(404).json({
        success: false,
        message: 'Role not assigned to user'
      });
    }

    logger.info('Role removed from user', {
      userId: user.id,
      roleId,
      removedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Role removed from user successfully'
    });
  } catch (error) {
    logger.error('Error removing role from user:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Set user roles (replace all)
 */
export const setUserRoles = async (req, res) => {
  try {
    const { userId } = req.params;
    const { roles = [] } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Validate all roles exist
    if (roles.length > 0) {
      for (const roleId of roles) {
        const role = await Role.findById(roleId);
        if (!role) {
          return res.status(404).json({
            success: false,
            message: `Role with ID ${roleId} not found`
          });
        }
      }
    }

    await user.setRoles(roles);

    logger.info('User roles set', {
      userId: user.id,
      roleCount: roles.length,
      setBy: req.user.id
    });

    res.json({
      success: true,
      message: 'User roles updated successfully'
    });
  } catch (error) {
    logger.error('Error setting user roles:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get user roles
 */
export const getUserRoles = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const roles = await user.getRoles();

    res.json({
      success: true,
      message: 'User roles retrieved successfully',
      data: {
        user_id: user.id,
        email: user.email,
        roles
      }
    });
  } catch (error) {
    logger.error('Error getting user roles:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get user permissions
 */
export const getUserPermissions = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const permissions = await user.getPermissions();

    res.json({
      success: true,
      message: 'User permissions retrieved successfully',
      data: {
        user_id: user.id,
        email: user.email,
        permissions
      }
    });
  } catch (error) {
    logger.error('Error getting user permissions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Reset user failed login attempts
 */
export const resetUserFailedLogins = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await user.resetFailedLogins();

    logger.info('User failed login attempts reset', {
      userId: user.id,
      resetBy: req.user.id
    });

    res.json({
      success: true,
      message: 'User failed login attempts reset successfully'
    });
  } catch (error) {
    logger.error('Error resetting user failed logins:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Disable user 2FA (admin action)
 */
export const disableUser2FA = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.two_factor_enabled) {
      return res.status(400).json({
        success: false,
        message: 'User does not have 2FA enabled'
      });
    }

    await user.disable2FA();

    logger.info('User 2FA disabled by admin', {
      userId: user.id,
      disabledBy: req.user.id
    });

    res.json({
      success: true,
      message: 'User 2FA disabled successfully'
    });
  } catch (error) {
    logger.error('Error disabling user 2FA:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get user statistics
 */
export const getUserStats = async (req, res) => {
  try {
    const statsQuery = `
      SELECT 
        COUNT(*) as total_users,
        COUNT(*) FILTER (WHERE status = 'active') as active_users,
        COUNT(*) FILTER (WHERE status = 'inactive') as inactive_users,
        COUNT(*) FILTER (WHERE status = 'suspended') as suspended_users,
        COUNT(*) FILTER (WHERE email_verified = true) as verified_users,
        COUNT(*) FILTER (WHERE two_factor_enabled = true) as two_factor_users,
        COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '30 days') as new_users_30d,
        COUNT(*) FILTER (WHERE last_login >= CURRENT_DATE - INTERVAL '30 days') as active_users_30d
      FROM users
    `;

    const roleStatsQuery = `
      SELECT r.name, COUNT(ur.user_id) as user_count
      FROM roles r
      LEFT JOIN user_roles ur ON r.id = ur.role_id
      GROUP BY r.id, r.name
      ORDER BY user_count DESC
    `;

    const [statsResult, roleStatsResult] = await Promise.all([
      query(statsQuery),
      query(roleStatsQuery)
    ]);

    res.json({
      success: true,
      message: 'User statistics retrieved successfully',
      data: {
        user_stats: statsResult.rows[0],
        role_distribution: roleStatsResult.rows
      }
    });
  } catch (error) {
    logger.error('Error getting user statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

export default {
  getUsers,
  getUserById,
  updateUserStatus,
  assignRoleToUser,
  removeRoleFromUser,
  setUserRoles,
  getUserRoles,
  getUserPermissions,
  resetUserFailedLogins,
  disableUser2FA,
  getUserStats
}; 
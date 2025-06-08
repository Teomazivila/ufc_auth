import express from 'express';
import { body, param, query } from 'express-validator';
import { authenticateToken } from '../middleware/auth.js';
import { requirePermission, requireAdmin, requireOwnershipOrAdmin } from '../middleware/authorization.js';
import {
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
} from '../controllers/userManagementController.js';

const router = express.Router();

/**
 * User Management Routes for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

// Validation schemas
const userIdValidation = [
  param('userId')
    .isUUID()
    .withMessage('User ID must be a valid UUID')
];

const updateStatusValidation = [
  param('userId')
    .isUUID()
    .withMessage('User ID must be a valid UUID'),
  body('status')
    .isIn(['active', 'inactive', 'suspended'])
    .withMessage('Status must be one of: active, inactive, suspended')
];

const assignRoleValidation = [
  param('userId')
    .isUUID()
    .withMessage('User ID must be a valid UUID'),
  body('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID')
];

const removeRoleValidation = [
  param('userId')
    .isUUID()
    .withMessage('User ID must be a valid UUID'),
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID')
];

const setRolesValidation = [
  param('userId')
    .isUUID()
    .withMessage('User ID must be a valid UUID'),
  body('roles')
    .isArray()
    .withMessage('Roles must be an array'),
  body('roles.*')
    .isUUID()
    .withMessage('Each role must be a valid UUID')
];

const userListValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Search term cannot exceed 100 characters'),
  query('status')
    .optional()
    .isIn(['active', 'inactive', 'suspended'])
    .withMessage('Status must be one of: active, inactive, suspended'),
  query('role')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Role filter cannot exceed 50 characters'),
  query('sortBy')
    .optional()
    .isIn(['created_at', 'email', 'username', 'first_name', 'last_name', 'status', 'last_login'])
    .withMessage('Invalid sort field'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc')
];

const paginationValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
];

// Routes

/**
 * @route   GET /api/users
 * @desc    Get all users with pagination and filtering
 * @access  Users with 'users:read' permission
 */
router.get('/',
  authenticateToken,
  requirePermission('users:read'),
  userListValidation,
  getUsers
);

/**
 * @route   GET /api/users/stats
 * @desc    Get user statistics
 * @access  Admin only
 */
router.get('/stats',
  authenticateToken,
  requireAdmin,
  getUserStats
);

/**
 * @route   GET /api/users/:userId
 * @desc    Get user by ID with roles and permissions
 * @access  Owner or users with 'users:read' permission
 */
router.get('/:userId',
  authenticateToken,
  requireOwnershipOrAdmin(),
  userIdValidation,
  getUserById
);

/**
 * @route   PUT /api/users/:userId/status
 * @desc    Update user status
 * @access  Admin only
 */
router.put('/:userId/status',
  authenticateToken,
  requireAdmin,
  updateStatusValidation,
  updateUserStatus
);

/**
 * @route   POST /api/users/:userId/roles
 * @desc    Assign role to user
 * @access  Admin only
 */
router.post('/:userId/roles',
  authenticateToken,
  requireAdmin,
  assignRoleValidation,
  assignRoleToUser
);

/**
 * @route   DELETE /api/users/:userId/roles/:roleId
 * @desc    Remove role from user
 * @access  Admin only
 */
router.delete('/:userId/roles/:roleId',
  authenticateToken,
  requireAdmin,
  removeRoleValidation,
  removeRoleFromUser
);

/**
 * @route   PUT /api/users/:userId/roles
 * @desc    Set user roles (replace all)
 * @access  Admin only
 */
router.put('/:userId/roles',
  authenticateToken,
  requireAdmin,
  setRolesValidation,
  setUserRoles
);

/**
 * @route   GET /api/users/:userId/roles
 * @desc    Get user roles
 * @access  Owner or users with 'users:read' permission
 */
router.get('/:userId/roles',
  authenticateToken,
  requireOwnershipOrAdmin(),
  userIdValidation,
  getUserRoles
);

/**
 * @route   GET /api/users/:userId/permissions
 * @desc    Get user permissions
 * @access  Owner or users with 'users:read' permission
 */
router.get('/:userId/permissions',
  authenticateToken,
  requireOwnershipOrAdmin(),
  userIdValidation,
  getUserPermissions
);

/**
 * @route   POST /api/users/:userId/reset-failed-logins
 * @desc    Reset user failed login attempts
 * @access  Admin only
 */
router.post('/:userId/reset-failed-logins',
  authenticateToken,
  requireAdmin,
  userIdValidation,
  resetUserFailedLogins
);

/**
 * @route   POST /api/users/:userId/disable-2fa
 * @desc    Disable user 2FA (admin action)
 * @access  Admin only
 */
router.post('/:userId/disable-2fa',
  authenticateToken,
  requireAdmin,
  userIdValidation,
  disableUser2FA
);

export default router; 
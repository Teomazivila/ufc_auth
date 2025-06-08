import express from 'express';
import { body, param, query } from 'express-validator';
import { authenticateToken } from '../middleware/auth.js';
import { requirePermission, requireAdmin } from '../middleware/authorization.js';
import {
  createRole,
  getRoles,
  getRoleById,
  updateRole,
  deleteRole,
  assignPermissionToRole,
  removePermissionFromRole,
  setRolePermissions,
  getRolePermissions,
  getRoleUsers
} from '../controllers/roleController.js';

const router = express.Router();

/**
 * Role Routes for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

// Validation schemas
const createRoleValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Role name can only contain letters, numbers, underscores, and hyphens'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Description cannot exceed 255 characters'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .optional()
    .isUUID()
    .withMessage('Each permission must be a valid UUID')
];

const updateRoleValidation = [
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Role name can only contain letters, numbers, underscores, and hyphens'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Description cannot exceed 255 characters')
];

const roleIdValidation = [
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID')
];

const assignPermissionValidation = [
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID'),
  body('permissionId')
    .isUUID()
    .withMessage('Permission ID must be a valid UUID')
];

const removePermissionValidation = [
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID'),
  param('permissionId')
    .isUUID()
    .withMessage('Permission ID must be a valid UUID')
];

const setPermissionsValidation = [
  param('roleId')
    .isUUID()
    .withMessage('Role ID must be a valid UUID'),
  body('permissions')
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .isUUID()
    .withMessage('Each permission must be a valid UUID')
];

const paginationValidation = [
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
  query('includePermissions')
    .optional()
    .isBoolean()
    .withMessage('includePermissions must be a boolean')
];

// Routes

/**
 * @route   POST /api/roles
 * @desc    Create a new role
 * @access  Admin only
 */
router.post('/',
  authenticateToken,
  requireAdmin,
  createRoleValidation,
  createRole
);

/**
 * @route   GET /api/roles
 * @desc    Get all roles with pagination
 * @access  Users with 'roles:read' permission
 */
router.get('/',
  authenticateToken,
  requirePermission('roles:read'),
  paginationValidation,
  getRoles
);

/**
 * @route   GET /api/roles/:roleId
 * @desc    Get role by ID
 * @access  Users with 'roles:read' permission
 */
router.get('/:roleId',
  authenticateToken,
  requirePermission('roles:read'),
  roleIdValidation,
  getRoleById
);

/**
 * @route   PUT /api/roles/:roleId
 * @desc    Update role
 * @access  Admin only
 */
router.put('/:roleId',
  authenticateToken,
  requireAdmin,
  updateRoleValidation,
  updateRole
);

/**
 * @route   DELETE /api/roles/:roleId
 * @desc    Delete role
 * @access  Admin only
 */
router.delete('/:roleId',
  authenticateToken,
  requireAdmin,
  roleIdValidation,
  deleteRole
);

/**
 * @route   POST /api/roles/:roleId/permissions
 * @desc    Assign permission to role
 * @access  Admin only
 */
router.post('/:roleId/permissions',
  authenticateToken,
  requireAdmin,
  assignPermissionValidation,
  assignPermissionToRole
);

/**
 * @route   DELETE /api/roles/:roleId/permissions/:permissionId
 * @desc    Remove permission from role
 * @access  Admin only
 */
router.delete('/:roleId/permissions/:permissionId',
  authenticateToken,
  requireAdmin,
  removePermissionValidation,
  removePermissionFromRole
);

/**
 * @route   PUT /api/roles/:roleId/permissions
 * @desc    Set role permissions (replace all)
 * @access  Admin only
 */
router.put('/:roleId/permissions',
  authenticateToken,
  requireAdmin,
  setPermissionsValidation,
  setRolePermissions
);

/**
 * @route   GET /api/roles/:roleId/permissions
 * @desc    Get role permissions
 * @access  Users with 'roles:read' permission
 */
router.get('/:roleId/permissions',
  authenticateToken,
  requirePermission('roles:read'),
  roleIdValidation,
  getRolePermissions
);

/**
 * @route   GET /api/roles/:roleId/users
 * @desc    Get users assigned to role
 * @access  Users with 'users:read' permission
 */
router.get('/:roleId/users',
  authenticateToken,
  requirePermission('users:read'),
  [
    ...roleIdValidation,
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100')
  ],
  getRoleUsers
);

export default router; 
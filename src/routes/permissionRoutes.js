import express from 'express';
import { body, param, query } from 'express-validator';
import { authenticateToken } from '../middleware/auth.js';
import { requirePermission, requireAdmin } from '../middleware/authorization.js';
import {
  createPermission,
  getPermissions,
  getPermissionById,
  updatePermission,
  deletePermission,
  getResources,
  getActions,
  getPermissionsByResource,
  getPermissionRoles,
  createBulkPermissions
} from '../controllers/permissionController.js';

const router = express.Router();

/**
 * Permission Routes for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

// Validation schemas
const createPermissionValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Permission name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9_:-]+$/)
    .withMessage('Permission name can only contain letters, numbers, underscores, colons, and hyphens'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Description cannot exceed 255 characters'),
  body('resource')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Resource must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Resource can only contain letters, numbers, underscores, and hyphens'),
  body('action')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Action must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Action can only contain letters, numbers, underscores, and hyphens')
];

const updatePermissionValidation = [
  param('permissionId')
    .isUUID()
    .withMessage('Permission ID must be a valid UUID'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Permission name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9_:-]+$/)
    .withMessage('Permission name can only contain letters, numbers, underscores, colons, and hyphens'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Description cannot exceed 255 characters'),
  body('resource')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Resource must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Resource can only contain letters, numbers, underscores, and hyphens'),
  body('action')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Action must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Action can only contain letters, numbers, underscores, and hyphens')
];

const permissionIdValidation = [
  param('permissionId')
    .isUUID()
    .withMessage('Permission ID must be a valid UUID')
];

const resourceValidation = [
  param('resource')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Resource must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Resource can only contain letters, numbers, underscores, and hyphens')
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
  query('resource')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Resource filter cannot exceed 50 characters'),
  query('action')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Action filter cannot exceed 50 characters')
];

const bulkCreateValidation = [
  body('permissions')
    .isArray({ min: 1, max: 50 })
    .withMessage('Permissions must be an array with 1-50 items'),
  body('permissions.*.name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Permission name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9_:-]+$/)
    .withMessage('Permission name can only contain letters, numbers, underscores, colons, and hyphens'),
  body('permissions.*.description')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Description cannot exceed 255 characters'),
  body('permissions.*.resource')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Resource must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Resource can only contain letters, numbers, underscores, and hyphens'),
  body('permissions.*.action')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Action must be between 2 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Action can only contain letters, numbers, underscores, and hyphens')
];

// Routes

/**
 * @route   POST /api/permissions
 * @desc    Create a new permission
 * @access  Admin only
 */
router.post('/',
  authenticateToken,
  requireAdmin,
  createPermissionValidation,
  createPermission
);

/**
 * @route   POST /api/permissions/bulk
 * @desc    Create multiple permissions at once
 * @access  Admin only
 */
router.post('/bulk',
  authenticateToken,
  requireAdmin,
  bulkCreateValidation,
  createBulkPermissions
);

/**
 * @route   GET /api/permissions
 * @desc    Get all permissions with pagination and filtering
 * @access  Users with 'permissions:read' permission
 */
router.get('/',
  authenticateToken,
  requirePermission('permissions:read'),
  paginationValidation,
  getPermissions
);

/**
 * @route   GET /api/permissions/resources
 * @desc    Get all unique resources
 * @access  Users with 'permissions:read' permission
 */
router.get('/resources',
  authenticateToken,
  requirePermission('permissions:read'),
  getResources
);

/**
 * @route   GET /api/permissions/actions
 * @desc    Get all unique actions
 * @access  Users with 'permissions:read' permission
 */
router.get('/actions',
  authenticateToken,
  requirePermission('permissions:read'),
  getActions
);

/**
 * @route   GET /api/permissions/resource/:resource
 * @desc    Get permissions by resource
 * @access  Users with 'permissions:read' permission
 */
router.get('/resource/:resource',
  authenticateToken,
  requirePermission('permissions:read'),
  resourceValidation,
  getPermissionsByResource
);

/**
 * @route   GET /api/permissions/:permissionId
 * @desc    Get permission by ID
 * @access  Users with 'permissions:read' permission
 */
router.get('/:permissionId',
  authenticateToken,
  requirePermission('permissions:read'),
  permissionIdValidation,
  getPermissionById
);

/**
 * @route   PUT /api/permissions/:permissionId
 * @desc    Update permission
 * @access  Admin only
 */
router.put('/:permissionId',
  authenticateToken,
  requireAdmin,
  updatePermissionValidation,
  updatePermission
);

/**
 * @route   DELETE /api/permissions/:permissionId
 * @desc    Delete permission
 * @access  Admin only
 */
router.delete('/:permissionId',
  authenticateToken,
  requireAdmin,
  permissionIdValidation,
  deletePermission
);

/**
 * @route   GET /api/permissions/:permissionId/roles
 * @desc    Get roles that have this permission
 * @access  Users with 'roles:read' permission
 */
router.get('/:permissionId/roles',
  authenticateToken,
  requirePermission('roles:read'),
  [
    ...permissionIdValidation,
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100')
  ],
  getPermissionRoles
);

export default router; 
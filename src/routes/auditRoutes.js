import { Router } from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { requirePermission } from '../middleware/authorization.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  getAuditLogs,
  getSecurityAnalytics,
  exportAuditLogs,
  getAuditStatistics,
  searchAuditLogs,
  performMaintenance
} from '../controllers/auditController.js';

const router = Router();

/**
 * Audit Routes - Following 2025 IAM Best Practices
 * Implements secure access to centralized audit logs
 * Reference: StrongDM IAM Best Practices 2025
 */

/**
 * @route   GET /api/v1/audit/logs
 * @desc    Get audit logs with filtering and pagination
 * @access  Admin with audit:read permission
 */
router.get('/logs',
  authenticateToken,
  requirePermission('audit:read'),
  asyncHandler(getAuditLogs)
);

/**
 * @route   GET /api/v1/audit/analytics
 * @desc    Get security analytics dashboard data
 * @access  Admin with audit:read permission
 */
router.get('/analytics',
  authenticateToken,
  requirePermission('audit:read'),
  asyncHandler(getSecurityAnalytics)
);

/**
 * @route   GET /api/v1/audit/statistics
 * @desc    Get high-level audit statistics
 * @access  Admin with audit:read permission
 */
router.get('/statistics',
  authenticateToken,
  requirePermission('audit:read'),
  asyncHandler(getAuditStatistics)
);

/**
 * @route   GET /api/v1/audit/search
 * @desc    Search audit logs with advanced filtering
 * @access  Admin with audit:read permission
 */
router.get('/search',
  authenticateToken,
  requirePermission('audit:read'),
  asyncHandler(searchAuditLogs)
);

/**
 * @route   GET /api/v1/audit/export
 * @desc    Export audit logs for compliance (JSON/CSV)
 * @access  Admin with audit:export permission
 */
router.get('/export',
  authenticateToken,
  requirePermission('audit:export'),
  asyncHandler(exportAuditLogs)
);

/**
 * @route   POST /api/v1/audit/maintenance
 * @desc    Perform system maintenance (clean expired tokens)
 * @access  Admin with system:admin permission
 */
router.post('/maintenance',
  authenticateToken,
  requirePermission('system:admin'),
  asyncHandler(performMaintenance)
);

export default router; 
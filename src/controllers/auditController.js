import { AuditLog } from '../models/AuditLog.js';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../middleware/errorHandler.js';

/**
 * Audit Controller - Following 2025 IAM Best Practices
 * Implements centralized log collection and security monitoring
 * Reference: StrongDM IAM Best Practices 2025 - Centralized Log Collection
 */

/**
 * Get audit logs with filtering and pagination
 * Implements comprehensive audit trail access for compliance
 */
export const getAuditLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      user_id,
      action,
      resource,
      success,
      start_date,
      end_date,
      ip_address,
      search
    } = req.query;

    // Validate pagination limits (following least privilege principles)
    const validatedLimit = Math.min(parseInt(limit), 100);
    const validatedPage = Math.max(parseInt(page), 1);

    // Build filters
    const filters = {
      page: validatedPage,
      limit: validatedLimit
    };

    if (user_id) filters.user_id = user_id;
    if (action) filters.action = action;
    if (resource) filters.resource = resource;
    if (success !== undefined) filters.success = success === 'true';
    if (start_date) filters.start_date = new Date(start_date);
    if (end_date) filters.end_date = new Date(end_date);
    if (ip_address) filters.ip_address = ip_address;

    // Validate date range (max 90 days for performance)
    if (filters.start_date && filters.end_date) {
      const daysDiff = (filters.end_date - filters.start_date) / (1000 * 60 * 60 * 24);
      if (daysDiff > 90) {
        throw new ValidationError('Date range cannot exceed 90 days');
      }
    }

    const result = await AuditLog.getAuditLogs(filters);

    // Log audit access for security monitoring
    await AuditLog.logSecurityEvent('AUDIT_LOGS_ACCESSED', req, {
      filters,
      resultCount: result.logs.length,
      userId: req.user.id
    });

    res.json({
      success: true,
      data: {
        logs: result.logs,
        pagination: result.pagination,
        filters: filters
      }
    });
  } catch (error) {
    logger.error('Error getting audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while retrieving audit logs'
    });
  }
};

/**
 * Get security analytics dashboard
 * Implements continuous monitoring and threat detection
 */
export const getSecurityAnalytics = async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;

    // Validate time range
    const validTimeRanges = ['24h', '7d', '30d'];
    if (!validTimeRanges.includes(timeRange)) {
      throw new ValidationError('Invalid time range. Must be one of: 24h, 7d, 30d');
    }

    const analytics = await AuditLog.getSecurityAnalytics(timeRange);

    // Log analytics access
    await AuditLog.logSecurityEvent('SECURITY_ANALYTICS_ACCESSED', req, {
      timeRange,
      userId: req.user.id
    });

    res.json({
      success: true,
      data: {
        analytics,
        timeRange,
        generated_at: new Date().toISOString()
      }
    });
  } catch (error) {
    logger.error('Error getting security analytics:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while retrieving security analytics'
    });
  }
};

/**
 * Export audit logs for compliance
 * Supports regulatory requirements and external SIEM integration
 */
export const exportAuditLogs = async (req, res) => {
  try {
    const {
      format = 'json',
      user_id,
      action,
      resource,
      success,
      start_date,
      end_date,
      ip_address
    } = req.query;

    // Validate export format
    const validFormats = ['json', 'csv'];
    if (!validFormats.includes(format)) {
      throw new ValidationError('Invalid export format. Must be json or csv');
    }

    // Build export filters
    const filters = {};
    if (user_id) filters.user_id = user_id;
    if (action) filters.action = action;
    if (resource) filters.resource = resource;
    if (success !== undefined) filters.success = success === 'true';
    if (start_date) filters.start_date = new Date(start_date);
    if (end_date) filters.end_date = new Date(end_date);
    if (ip_address) filters.ip_address = ip_address;

    // Limit export size for performance (max 30 days)
    if (filters.start_date && filters.end_date) {
      const daysDiff = (filters.end_date - filters.start_date) / (1000 * 60 * 60 * 24);
      if (daysDiff > 30) {
        throw new ValidationError('Export date range cannot exceed 30 days');
      }
    }

    const exportData = await AuditLog.exportAuditLogs(filters, format);

    // Log export for security tracking
    await AuditLog.logSecurityEvent('AUDIT_LOGS_EXPORTED', req, {
      format,
      filters,
      recordCount: Array.isArray(exportData) ? exportData.length : 'csv',
      userId: req.user.id
    });

    // Set appropriate headers for download
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `audit_logs_${timestamp}.${format}`;

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(exportData);
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.json(exportData);
    }

  } catch (error) {
    logger.error('Error exporting audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while exporting audit logs'
    });
  }
};

/**
 * Get audit log statistics
 * Provides high-level metrics for dashboard display
 */
export const getAuditStatistics = async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;

    // Get analytics data
    const analytics = await AuditLog.getSecurityAnalytics(timeRange);

    // Calculate additional statistics
    const failureRate = analytics.total_events > 0 
      ? ((analytics.failed_events / analytics.total_events) * 100).toFixed(2)
      : 0;

    const twoFactorUsage = analytics.total_events > 0
      ? ((analytics.two_factor_events / analytics.total_events) * 100).toFixed(2)
      : 0;

    const stats = {
      total_events: parseInt(analytics.total_events),
      failed_events: parseInt(analytics.failed_events),
      failure_rate: parseFloat(failureRate),
      successful_logins: parseInt(analytics.successful_logins),
      failed_logins: parseInt(analytics.failed_logins),
      two_factor_events: parseInt(analytics.two_factor_events),
      two_factor_usage_rate: parseFloat(twoFactorUsage),
      unique_users: parseInt(analytics.unique_users),
      unique_ips: parseInt(analytics.unique_ips),
      top_failed_actions: analytics.top_failed_actions || [],
      suspicious_ips: analytics.suspicious_ips || [],
      time_range: timeRange,
      generated_at: new Date().toISOString()
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error getting audit statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while retrieving statistics'
    });
  }
};

/**
 * Search audit logs
 * Advanced search functionality for security investigations
 */
export const searchAuditLogs = async (req, res) => {
  try {
    const {
      q: searchQuery,
      page = 1,
      limit = 50,
      type = 'all' // all, security, authentication, authorization
    } = req.query;

    if (!searchQuery || searchQuery.trim().length < 3) {
      throw new ValidationError('Search query must be at least 3 characters long');
    }

    const validatedLimit = Math.min(parseInt(limit), 100);
    const validatedPage = Math.max(parseInt(page), 1);

    // Build search filters based on type
    const filters = {
      page: validatedPage,
      limit: validatedLimit
    };

    // Add type-specific filters
    switch (type) {
      case 'security':
        filters.resource = 'security';
        break;
      case 'authentication':
        filters.action = ['LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', '2FA_VERIFIED'];
        break;
      case 'authorization':
        filters.resource = ['users', 'roles', 'permissions'];
        break;
      default:
        // Search all
        break;
    }

    // For now, implement basic search by action or resource
    // In production, you might want to implement full-text search
    if (searchQuery) {
      // Simple search implementation - can be enhanced with database full-text search
      const searchTerms = searchQuery.toLowerCase().split(' ');
      filters.search_terms = searchTerms;
    }

    const result = await AuditLog.getAuditLogs(filters);

    // Log search activity
    await AuditLog.logSecurityEvent('AUDIT_LOGS_SEARCHED', req, {
      searchQuery,
      type,
      resultCount: result.logs.length,
      userId: req.user.id
    });

    res.json({
      success: true,
      data: {
        logs: result.logs,
        pagination: result.pagination,
        search: {
          query: searchQuery,
          type,
          terms: searchQuery.toLowerCase().split(' ')
        }
      }
    });
  } catch (error) {
    logger.error('Error searching audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while searching audit logs'
    });
  }
};

/**
 * Clean expired tokens and logs (maintenance endpoint)
 * Implements security hygiene following 2025 best practices
 */
export const performMaintenance = async (req, res) => {
  try {
    const { User } = await import('../models/User.js');
    
    // Clean expired password reset tokens
    const tokensCleared = await User.cleanExpiredResetTokens();

    // In production, you might also clean old audit logs based on retention policy
    // const oldLogsCleared = await AuditLog.cleanOldLogs(retentionDays);

    // Log maintenance activity
    await AuditLog.logSecurityEvent('SYSTEM_MAINTENANCE_PERFORMED', req, {
      tokensCleared,
      performedBy: req.user.id
    });

    res.json({
      success: true,
      data: {
        message: 'Maintenance completed successfully',
        results: {
          expired_tokens_cleared: tokensCleared
        }
      }
    });
  } catch (error) {
    logger.error('Error performing maintenance:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during maintenance'
    });
  }
}; 
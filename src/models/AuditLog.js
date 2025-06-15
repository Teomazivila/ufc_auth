import { query } from '../config/database.js';
import { logger } from '../utils/logger.js';

/**
 * AuditLog Model - Following 2025 IAM Best Practices
 * Implements centralized log collection and comprehensive audit trails
 * Reference: StrongDM IAM Best Practices 2025
 */
export class AuditLog {
  constructor(auditData) {
    this.id = auditData.id;
    this.user_id = auditData.user_id;
    this.action = auditData.action;
    this.resource = auditData.resource;
    this.resource_id = auditData.resource_id;
    this.details = auditData.details;
    this.ip_address = auditData.ip_address;
    this.user_agent = auditData.user_agent;
    this.success = auditData.success;
    this.error_message = auditData.error_message;
    this.created_at = auditData.created_at;
  }

  /**
   * Create audit log entry
   * Implements Zero Trust principle: "never trust, always verify"
   */
  static async create(auditData) {
    try {
      const queryText = `
        INSERT INTO audit_logs (
          user_id, action, resource, resource_id, details, 
          ip_address, user_agent, success, error_message
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
      `;

      const values = [
        auditData.user_id || null,
        auditData.action,
        auditData.resource || null,
        auditData.resource_id || null,
        JSON.stringify(auditData.details || {}),
        auditData.ip_address || null,
        auditData.user_agent || null,
        auditData.success !== undefined ? auditData.success : true,
        auditData.error_message || null
      ];

      const result = await query(queryText, values);
      
      logger.debug('Audit log created', { 
        auditId: result.rows[0].id,
        action: auditData.action,
        resource: auditData.resource 
      });

      return new AuditLog(result.rows[0]);
    } catch (error) {
      logger.error('Error creating audit log:', error);
      throw error;
    }
  }

  /**
   * Get audit logs with filtering and pagination
   * Supports compliance reporting and security analysis
   */
  static async getAuditLogs(filters = {}) {
    try {
      let queryText = `
        SELECT 
          al.*,
          u.email as user_email,
          u.username,
          u.first_name,
          u.last_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE 1=1
      `;

      const values = [];
      let paramCount = 0;

      // Apply filters following least privilege access principles
      if (filters.user_id) {
        queryText += ` AND al.user_id = $${++paramCount}`;
        values.push(filters.user_id);
      }

      if (filters.action) {
        queryText += ` AND al.action = $${++paramCount}`;
        values.push(filters.action);
      }

      if (filters.resource) {
        queryText += ` AND al.resource = $${++paramCount}`;
        values.push(filters.resource);
      }

      if (filters.success !== undefined) {
        queryText += ` AND al.success = $${++paramCount}`;
        values.push(filters.success);
      }

      if (filters.start_date) {
        queryText += ` AND al.created_at >= $${++paramCount}`;
        values.push(filters.start_date);
      }

      if (filters.end_date) {
        queryText += ` AND al.created_at <= $${++paramCount}`;
        values.push(filters.end_date);
      }

      if (filters.ip_address) {
        queryText += ` AND al.ip_address = $${++paramCount}`;
        values.push(filters.ip_address);
      }

      // Apply pagination
      const page = filters.page || 1;
      const limit = Math.min(filters.limit || 50, 100); // Max 100 per page
      const offset = (page - 1) * limit;

      queryText += ` ORDER BY al.created_at DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
      values.push(limit, offset);

      const result = await query(queryText, values);

      // Get total count for pagination
      let countQuery = `
        SELECT COUNT(*) as total
        FROM audit_logs al
        WHERE 1=1
      `;

      const countValues = values.slice(0, -2); // Remove limit and offset
      let countParamCount = 0;

      if (filters.user_id) {
        countQuery += ` AND al.user_id = $${++countParamCount}`;
      }
      if (filters.action) {
        countQuery += ` AND al.action = $${++countParamCount}`;
      }
      if (filters.resource) {
        countQuery += ` AND al.resource = $${++countParamCount}`;
      }
      if (filters.success !== undefined) {
        countQuery += ` AND al.success = $${++countParamCount}`;
      }
      if (filters.start_date) {
        countQuery += ` AND al.created_at >= $${++countParamCount}`;
      }
      if (filters.end_date) {
        countQuery += ` AND al.created_at <= $${++countParamCount}`;
      }
      if (filters.ip_address) {
        countQuery += ` AND al.ip_address = $${++countParamCount}`;
      }

      const countResult = await query(countQuery, countValues);
      const total = parseInt(countResult.rows[0].total);

      return {
        logs: result.rows.map(row => new AuditLog(row)),
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting audit logs:', error);
      throw error;
    }
  }

  /**
   * Get security analytics
   * Implements continuous monitoring for threat detection
   */
  static async getSecurityAnalytics(timeRange = '24h') {
    try {
      const timeCondition = timeRange === '24h' ? "created_at >= NOW() - INTERVAL '24 hours'" :
                           timeRange === '7d' ? "created_at >= NOW() - INTERVAL '7 days'" :
                           timeRange === '30d' ? "created_at >= NOW() - INTERVAL '30 days'" :
                           "created_at >= NOW() - INTERVAL '24 hours'";

      const analyticsQuery = `
        SELECT 
          COUNT(*) as total_events,
          COUNT(CASE WHEN success = false THEN 1 END) as failed_events,
          COUNT(CASE WHEN action = 'LOGIN_FAILED' THEN 1 END) as failed_logins,
          COUNT(CASE WHEN action = 'LOGIN_SUCCESS' THEN 1 END) as successful_logins,
          COUNT(CASE WHEN action LIKE '%2FA%' THEN 1 END) as two_factor_events,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT ip_address) as unique_ips,
          
          -- Top failed actions
          (
            SELECT json_agg(row_to_json(t))
            FROM (
              SELECT action, COUNT(*) as count
              FROM audit_logs 
              WHERE ${timeCondition} AND success = false
              GROUP BY action
              ORDER BY count DESC
              LIMIT 10
            ) t
          ) as top_failed_actions,
          
          -- Suspicious IP activity
          (
            SELECT json_agg(row_to_json(t))
            FROM (
              SELECT ip_address, COUNT(*) as attempts, 
                     COUNT(CASE WHEN success = false THEN 1 END) as failed_attempts
              FROM audit_logs 
              WHERE ${timeCondition}
              GROUP BY ip_address
              HAVING COUNT(CASE WHEN success = false THEN 1 END) > 5
              ORDER BY failed_attempts DESC
              LIMIT 10
            ) t
          ) as suspicious_ips
          
        FROM audit_logs 
        WHERE ${timeCondition}
      `;

      const result = await query(analyticsQuery);
      const analytics = result.rows[0];

      // Parse JSON fields safely
      analytics.top_failed_actions = analytics.top_failed_actions ? 
        (typeof analytics.top_failed_actions === 'string' ? 
          JSON.parse(analytics.top_failed_actions) : analytics.top_failed_actions) : [];
      analytics.suspicious_ips = analytics.suspicious_ips ? 
        (typeof analytics.suspicious_ips === 'string' ? 
          JSON.parse(analytics.suspicious_ips) : analytics.suspicious_ips) : [];

      return analytics;
    } catch (error) {
      logger.error('Error getting security analytics:', error);
      throw error;
    }
  }

  /**
   * Export audit logs for compliance
   * Supports regulatory requirements and external SIEM integration
   */
  static async exportAuditLogs(filters = {}, format = 'json') {
    try {
      const { logs } = await this.getAuditLogs({
        ...filters,
        limit: 10000 // Large export limit
      });

      if (format === 'csv') {
        const csv = this.convertToCSV(logs);
        return csv;
      }

      return logs;
    } catch (error) {
      logger.error('Error exporting audit logs:', error);
      throw error;
    }
  }

  /**
   * Convert audit logs to CSV format
   */
  static convertToCSV(logs) {
    if (!logs.length) return '';

    const headers = [
      'timestamp', 'user_id', 'user_email', 'action', 'resource', 
      'resource_id', 'success', 'ip_address', 'user_agent', 'error_message'
    ];

    const csvRows = [headers.join(',')];

    logs.forEach(log => {
      const row = [
        log.created_at,
        log.user_id || '',
        log.user_email || '',
        log.action,
        log.resource || '',
        log.resource_id || '',
        log.success,
        log.ip_address || '',
        `"${(log.user_agent || '').replace(/"/g, '""')}"`,
        `"${(log.error_message || '').replace(/"/g, '""')}"`
      ];
      csvRows.push(row.join(','));
    });

    return csvRows.join('\n');
  }

  /**
   * Helper method to log common security events
   */
  static async logSecurityEvent(eventType, req, additionalData = {}) {
    const auditData = {
      user_id: req.user?.id || null,
      action: eventType,
      resource: 'security',
      ip_address: req.ip || req.connection?.remoteAddress,
      user_agent: req.get('User-Agent'),
      success: additionalData.success !== undefined ? additionalData.success : true,
      error_message: additionalData.error || null,
      details: {
        ...additionalData,
        url: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString()
      }
    };

    return await this.create(auditData);
  }
} 
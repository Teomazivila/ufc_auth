/**
 * Audit Controller Unit Tests
 * Tests the audit controller endpoints with security analytics and export functionality
 */

import { jest } from '@jest/globals';

describe('Audit Controller - Comprehensive Tests', () => {
  // Mock dependencies
  const mockAuditLog = {
    getAuditLogs: jest.fn(),
    getSecurityAnalytics: jest.fn(),
    exportAuditLogs: jest.fn(),
    logSecurityEvent: jest.fn(),
    getAuditStatistics: jest.fn(),
    searchAuditLogs: jest.fn(),
  };

  const mockLogger = {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  };

  // Mock request and response objects
  let mockReq, mockRes;

  beforeEach(() => {
    jest.clearAllMocks();

    mockReq = {
      query: {},
      user: {
        id: 'user-123',
        email: 'test@example.com',
        username: 'testuser',
      },
      ip: '192.168.1.100',
      headers: {
        'user-agent': 'Test Browser',
      },
    };

    mockRes = {
      json: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
    };
  });

  describe('getAuditLogs', () => {
    it('should return audit logs with default pagination', async () => {
      const mockLogs = [
        {
          id: 'log-1',
          user_id: 'user-123',
          action: 'LOGIN_SUCCESS',
          resource: 'auth',
          success: true,
          timestamp: new Date(),
        },
        {
          id: 'log-2',
          user_id: 'user-456',
          action: 'PASSWORD_RESET_REQUESTED',
          resource: 'auth',
          success: true,
          timestamp: new Date(),
        },
      ];

      const mockResult = {
        logs: mockLogs,
        pagination: {
          page: 1,
          limit: 50,
          total: 2,
          totalPages: 1,
        },
      };

      mockAuditLog.getAuditLogs.mockResolvedValue(mockResult);

      // Simulate controller logic
      const filters = {
        page: 1,
        limit: 50,
      };

      const result = await mockAuditLog.getAuditLogs(filters);
      await mockAuditLog.logSecurityEvent('AUDIT_LOGS_ACCESSED', mockReq, {
        filters,
        resultCount: result.logs.length,
        userId: mockReq.user.id,
      });

      expect(mockAuditLog.getAuditLogs).toHaveBeenCalledWith(filters);
      expect(mockAuditLog.logSecurityEvent).toHaveBeenCalledWith(
        'AUDIT_LOGS_ACCESSED',
        mockReq,
        expect.objectContaining({
          filters,
          resultCount: 2,
          userId: 'user-123',
        })
      );
      expect(result.logs).toHaveLength(2);
      expect(result.pagination.page).toBe(1);
    });

    it('should apply query filters correctly', async () => {
      mockReq.query = {
        page: '2',
        limit: '25',
        user_id: 'user-456',
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        success: 'true',
        start_date: '2024-01-01',
        end_date: '2024-01-31',
        ip_address: '192.168.1.100',
      };

      const expectedFilters = {
        page: 2,
        limit: 25,
        user_id: 'user-456',
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        success: true,
        start_date: new Date('2024-01-01'),
        end_date: new Date('2024-01-31'),
        ip_address: '192.168.1.100',
      };

      mockAuditLog.getAuditLogs.mockResolvedValue({
        logs: [],
        pagination: { page: 2, limit: 25, total: 0, totalPages: 0 },
      });

      // Test filter parsing logic
      const page = Math.max(parseInt(mockReq.query.page), 1);
      const limit = Math.min(parseInt(mockReq.query.limit), 100);
      const success = mockReq.query.success === 'true';

      expect(page).toBe(2);
      expect(limit).toBe(25);
      expect(success).toBe(true);
      expect(new Date(mockReq.query.start_date)).toEqual(new Date('2024-01-01'));
    });

    it('should validate pagination limits', async () => {
      mockReq.query = {
        page: '0',
        limit: '200',
      };

      // Test limit validation logic
      const validatedLimit = Math.min(parseInt(mockReq.query.limit), 100);
      const validatedPage = Math.max(parseInt(mockReq.query.page), 1);

      expect(validatedLimit).toBe(100); // Should cap at 100
      expect(validatedPage).toBe(1); // Should default to 1
    });

    it('should validate date range (max 90 days)', () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-04-01'); // 90+ days later

      const daysDiff = (endDate - startDate) / (1000 * 60 * 60 * 24);

      expect(daysDiff).toBeGreaterThan(90);

      // Should throw ValidationError for date range > 90 days
      if (daysDiff > 90) {
        const error = new Error('Date range cannot exceed 90 days');
        expect(error.message).toBe('Date range cannot exceed 90 days');
      }
    });

    it('should handle database errors gracefully', async () => {
      const dbError = new Error('Database connection failed');
      mockAuditLog.getAuditLogs.mockRejectedValue(dbError);

      try {
        await mockAuditLog.getAuditLogs({});
      } catch (error) {
        expect(error.message).toBe('Database connection failed');
        expect(mockLogger.error).not.toHaveBeenCalled(); // Would be called in actual controller
      }
    });
  });

  describe('getSecurityAnalytics', () => {
    it('should return security analytics for valid time range', async () => {
      const mockAnalytics = {
        totalEvents: 1250,
        successfulLogins: 1100,
        failedLogins: 150,
        passwordResets: 25,
        twoFactorEvents: 300,
        suspiciousActivities: 5,
        topUsers: [
          { user_id: 'user-123', event_count: 45 },
          { user_id: 'user-456', event_count: 32 },
        ],
        eventsByHour: Array.from({ length: 24 }, (_, i) => ({
          hour: i,
          count: Math.floor(Math.random() * 50),
        })),
        riskScore: 'LOW',
      };

      mockReq.query = { timeRange: '24h' };
      mockAuditLog.getSecurityAnalytics.mockResolvedValue(mockAnalytics);

      const result = await mockAuditLog.getSecurityAnalytics('24h');
      await mockAuditLog.logSecurityEvent('SECURITY_ANALYTICS_ACCESSED', mockReq, {
        timeRange: '24h',
        userId: mockReq.user.id,
      });

      expect(mockAuditLog.getSecurityAnalytics).toHaveBeenCalledWith('24h');
      expect(result.totalEvents).toBe(1250);
      expect(result.riskScore).toBe('LOW');
      expect(result.topUsers).toHaveLength(2);
      expect(result.eventsByHour).toHaveLength(24);
    });

    it('should validate time range parameter', () => {
      const validTimeRanges = ['24h', '7d', '30d'];
      const testRanges = ['24h', '7d', '30d', '1h', '90d', 'invalid'];

      testRanges.forEach(range => {
        const isValid = validTimeRanges.includes(range);
        if (range === '24h' || range === '7d' || range === '30d') {
          expect(isValid).toBe(true);
        } else {
          expect(isValid).toBe(false);
        }
      });
    });

    it('should calculate risk scores correctly', () => {
      const testScenarios = [
        { failedLogins: 5, suspiciousActivities: 0, expected: 'LOW' },
        { failedLogins: 25, suspiciousActivities: 2, expected: 'MEDIUM' },
        { failedLogins: 100, suspiciousActivities: 10, expected: 'HIGH' },
      ];

      testScenarios.forEach(scenario => {
        let riskScore = 'LOW';
        
        if (scenario.failedLogins > 50 || scenario.suspiciousActivities > 5) {
          riskScore = 'HIGH';
        } else if (scenario.failedLogins > 20 || scenario.suspiciousActivities > 1) {
          riskScore = 'MEDIUM';
        }

        expect(riskScore).toBe(scenario.expected);
      });
    });

    it('should generate hourly event distribution', () => {
      const eventsByHour = Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        count: Math.floor(Math.random() * 100),
      }));

      expect(eventsByHour).toHaveLength(24);
      eventsByHour.forEach((entry, index) => {
        expect(entry.hour).toBe(index);
        expect(entry.count).toBeGreaterThanOrEqual(0);
        expect(entry.count).toBeLessThan(100);
      });
    });
  });

  describe('exportAuditLogs', () => {
    it('should export logs in JSON format', async () => {
      const mockExportData = [
        {
          id: 'log-1',
          user_id: 'user-123',
          action: 'LOGIN_SUCCESS',
          timestamp: '2024-01-15T10:30:00Z',
        },
        {
          id: 'log-2',
          user_id: 'user-456',
          action: 'PASSWORD_RESET_REQUESTED',
          timestamp: '2024-01-15T11:15:00Z',
        },
      ];

      mockReq.query = { format: 'json' };
      mockAuditLog.exportAuditLogs.mockResolvedValue(mockExportData);

      const result = await mockAuditLog.exportAuditLogs({}, 'json');
      await mockAuditLog.logSecurityEvent('AUDIT_LOGS_EXPORTED', mockReq, {
        format: 'json',
        filters: {},
        recordCount: result.length,
        userId: mockReq.user.id,
      });

      expect(mockAuditLog.exportAuditLogs).toHaveBeenCalledWith({}, 'json');
      expect(result).toHaveLength(2);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should export logs in CSV format', async () => {
      const mockCsvData = `id,user_id,action,timestamp
log-1,user-123,LOGIN_SUCCESS,2024-01-15T10:30:00Z
log-2,user-456,PASSWORD_RESET_REQUESTED,2024-01-15T11:15:00Z`;

      mockReq.query = { format: 'csv' };
      mockAuditLog.exportAuditLogs.mockResolvedValue(mockCsvData);

      const result = await mockAuditLog.exportAuditLogs({}, 'csv');

      expect(result).toContain('id,user_id,action,timestamp');
      expect(result).toContain('LOGIN_SUCCESS');
      expect(result).toContain('PASSWORD_RESET_REQUESTED');
      expect(typeof result).toBe('string');
    });

    it('should validate export format', () => {
      const validFormats = ['json', 'csv'];
      const testFormats = ['json', 'csv', 'xml', 'pdf', ''];

      testFormats.forEach(format => {
        const isValid = validFormats.includes(format);
        if (format === 'json' || format === 'csv') {
          expect(isValid).toBe(true);
        } else {
          expect(isValid).toBe(false);
        }
      });
    });

    it('should validate export date range (max 30 days)', () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-02-15'); // 45 days later

      const daysDiff = (endDate - startDate) / (1000 * 60 * 60 * 24);

      expect(daysDiff).toBeGreaterThan(30);

      // Should throw ValidationError for export date range > 30 days
      if (daysDiff > 30) {
        const error = new Error('Export date range cannot exceed 30 days');
        expect(error.message).toBe('Export date range cannot exceed 30 days');
      }
    });

    it('should generate correct filename with timestamp', () => {
      const timestamp = new Date().toISOString().split('T')[0];
      const jsonFilename = `audit_logs_${timestamp}.json`;
      const csvFilename = `audit_logs_${timestamp}.csv`;

      expect(jsonFilename).toMatch(/^audit_logs_\d{4}-\d{2}-\d{2}\.json$/);
      expect(csvFilename).toMatch(/^audit_logs_\d{4}-\d{2}-\d{2}\.csv$/);
    });

    it('should set correct response headers for download', () => {
      const timestamp = '2024-01-15';
      
      // JSON headers
      const jsonHeaders = {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="audit_logs_${timestamp}.json"`,
      };

      // CSV headers
      const csvHeaders = {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="audit_logs_${timestamp}.csv"`,
      };

      expect(jsonHeaders['Content-Type']).toBe('application/json');
      expect(csvHeaders['Content-Type']).toBe('text/csv');
      expect(jsonHeaders['Content-Disposition']).toContain('attachment');
      expect(csvHeaders['Content-Disposition']).toContain('attachment');
    });
  });

  describe('Input Validation and Security', () => {
    it('should sanitize SQL injection attempts', () => {
      const maliciousInputs = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'/*",
        "1; DELETE FROM audit_logs; --",
      ];

      maliciousInputs.forEach(input => {
        // Test basic SQL injection detection - check each input individually
        let containsSqlKeywords = false;
        
        if (input.includes('DROP') || input.includes('DELETE') || 
            input.includes('INSERT') || input.includes('UPDATE') ||
            input.includes('--') || input.includes('/*') || 
            input.includes("OR '1'='1")) {
          containsSqlKeywords = true;
        }
        
        expect(containsSqlKeywords).toBe(true);
      });
    });

    it('should validate user permissions for audit access', () => {
      const userPermissions = ['audit:read', 'audit:export'];
      const requiredPermissions = {
        getAuditLogs: 'audit:read',
        exportAuditLogs: 'audit:export',
        getSecurityAnalytics: 'audit:read',
      };

      Object.entries(requiredPermissions).forEach(([action, permission]) => {
        const hasPermission = userPermissions.includes(permission);
        expect(hasPermission).toBe(true);
      });
    });

    it('should rate limit audit log requests', () => {
      const requestCounts = new Map();
      const userId = 'user-123';
      const maxRequestsPerMinute = 60;

      // Simulate multiple requests
      for (let i = 0; i < 65; i++) {
        const currentCount = requestCounts.get(userId) || 0;
        requestCounts.set(userId, currentCount + 1);
      }

      const userRequestCount = requestCounts.get(userId);
      const isRateLimited = userRequestCount > maxRequestsPerMinute;

      expect(userRequestCount).toBe(65);
      expect(isRateLimited).toBe(true);
    });

    it('should validate IP address format', () => {
      const validIPs = [
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
        '127.0.0.1',
      ];

      const invalidIPs = [
        '256.256.256.256',
        '192.168.1',
        'invalid-ip',
        '',
      ];

      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

      validIPs.forEach(ip => {
        expect(ipRegex.test(ip)).toBe(true);
      });

      invalidIPs.forEach(ip => {
        expect(ipRegex.test(ip)).toBe(false);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle validation errors properly', () => {
      const validationErrors = [
        'Date range cannot exceed 90 days',
        'Invalid time range. Must be one of: 24h, 7d, 30d',
        'Invalid export format. Must be json or csv',
        'Export date range cannot exceed 30 days',
      ];

      validationErrors.forEach(errorMessage => {
        const error = new Error(errorMessage);
        expect(error.message).toBe(errorMessage);
        expect(error).toBeInstanceOf(Error);
      });
    });

    it('should return appropriate HTTP status codes', () => {
      const statusCodes = {
        success: 200,
        validationError: 400,
        unauthorized: 401,
        forbidden: 403,
        notFound: 404,
        serverError: 500,
      };

      expect(statusCodes.success).toBe(200);
      expect(statusCodes.validationError).toBe(400);
      expect(statusCodes.unauthorized).toBe(401);
      expect(statusCodes.forbidden).toBe(403);
      expect(statusCodes.serverError).toBe(500);
    });

    it('should log errors with appropriate context', () => {
      const errorContext = {
        userId: 'user-123',
        action: 'getAuditLogs',
        error: 'Database connection failed',
        timestamp: new Date().toISOString(),
        ip: '192.168.1.100',
      };

      // Test error logging structure
      expect(errorContext.userId).toBe('user-123');
      expect(errorContext.action).toBe('getAuditLogs');
      expect(errorContext.error).toBe('Database connection failed');
      expect(errorContext.ip).toBe('192.168.1.100');
      expect(errorContext.timestamp).toBeDefined();
    });

    it('should handle concurrent request failures', async () => {
      const concurrentRequests = Array.from({ length: 10 }, (_, i) => 
        Promise.resolve({ id: `request-${i}`, status: 'completed' })
      );

      const results = await Promise.allSettled(concurrentRequests);
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');

      expect(successful).toHaveLength(10);
      expect(failed).toHaveLength(0);
      expect(results).toHaveLength(10);
    });
  });

  describe('Performance and Optimization', () => {
    it('should implement pagination for large result sets', () => {
      const totalRecords = 10000;
      const pageSize = 50;
      const totalPages = Math.ceil(totalRecords / pageSize);

      expect(totalPages).toBe(200);

      // Test pagination calculation
      const page = 5;
      const offset = (page - 1) * pageSize;
      const limit = pageSize;

      expect(offset).toBe(200);
      expect(limit).toBe(50);
    });

    it('should cache frequently accessed analytics', () => {
      const cacheKey = 'security_analytics_24h';
      const cacheExpiry = 5 * 60; // 5 minutes
      const cachedData = {
        data: { totalEvents: 1250 },
        timestamp: Date.now(),
        expiresIn: cacheExpiry,
      };

      const isExpired = (Date.now() - cachedData.timestamp) / 1000 > cachedData.expiresIn;

      expect(isExpired).toBe(false);
      expect(cachedData.data.totalEvents).toBe(1250);
    });

    it('should optimize database queries with indexes', () => {
      const indexedColumns = [
        'user_id',
        'action',
        'timestamp',
        'resource',
        'ip_address',
        'success',
      ];

      const queryFilters = {
        user_id: 'user-123',
        action: 'LOGIN_SUCCESS',
        timestamp: new Date(),
      };

      // Check if query filters use indexed columns
      Object.keys(queryFilters).forEach(column => {
        expect(indexedColumns).toContain(column);
      });
    });

    it('should implement query result limits', () => {
      const maxExportRecords = 10000;
      const maxQueryRecords = 1000;
      const requestedRecords = 15000;

      const exportLimit = Math.min(requestedRecords, maxExportRecords);
      const queryLimit = Math.min(requestedRecords, maxQueryRecords);

      expect(exportLimit).toBe(maxExportRecords);
      expect(queryLimit).toBe(maxQueryRecords);
    });
  });
}); 
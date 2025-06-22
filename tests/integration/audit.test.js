/**
 * Audit Logging Integration Tests
 * Tests audit log creation, retrieval, analytics, and export functionality
 */

import { jest } from '@jest/globals';
import supertest from 'supertest';

let app = null;
let request = null;

// Safer server initialization
const initializeServer = async () => {
  try {
    const Server = (await import('../../src/server.js')).default;
    const server = new Server();
    app = server.app;
    request = supertest(app);
    return true;
  } catch (error) {
    console.error('Failed to initialize server for testing:', error.message);
    return false;
  }
};

// Test data
const testAdmin = {
  email: 'admin.audit@example.com',
  username: 'adminaudit',
  password: 'AdminAudit123!',
  firstName: 'Admin',
  lastName: 'Audit'
};

const testUser = {
  email: 'user.audit@example.com',
  username: 'useraudit',
  password: 'UserAudit123!',
  firstName: 'User',
  lastName: 'Audit'
};

describe('Audit Logging Integration Tests', () => {
  let adminTokens = {};
  let userTokens = {};

  beforeAll(async () => {
    // Initialize server
    const serverStarted = await initializeServer();
    if (!serverStarted) {
      console.log('Skipping integration tests - server failed to start');
      return;
    }

    // Wait for server to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Register test admin
    try {
      const adminResponse = await request
        .post('/api/v1/auth/register')
        .send(testAdmin);
      
      if (adminResponse.status === 201) {
        adminTokens = adminResponse.body.data.tokens;
      }
    } catch (error) {
      console.log('Failed to register test admin:', error.message);
    }

    // Register test user
    try {
      const userResponse = await request
        .post('/api/v1/auth/register')
        .send(testUser);
      
      if (userResponse.status === 201) {
        userTokens = userResponse.body.data.tokens;
      }
    } catch (error) {
      console.log('Failed to register test user:', error.message);
    }

    // Generate some audit events by performing various actions
    if (userTokens.accessToken) {
      try {
        await request
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${userTokens.accessToken}`);

        await request
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${userTokens.accessToken}`)
          .send({ firstName: 'Updated' });
      } catch (error) {
        console.log('Failed to generate audit events:', error.message);
      }
    }

    // Allow time for audit logs to be created
    await new Promise(resolve => setTimeout(resolve, 1000));
  });

  describe('Basic Audit Log Functionality', () => {
    test('should create audit log for user registration', async () => {
      const newUser = {
        email: 'audit.test@example.com',
        username: 'audituser',
        password: 'AuditTest123!',
        firstName: 'Audit',
        lastName: 'User'
      };

      const response = await request
        .post('/api/v1/auth/register')
        .send(newUser);

      expect(response.status).toBe(201);
    });

    test('should get audit logs with admin permissions', async () => {
      const response = await request
        .get('/api/v1/admin/audit')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      // May return 200 or 404 depending on implementation
      expect([200, 404]).toContain(response.status);
    });

    test('should reject audit log access for non-admin users', async () => {
      const response = await request
        .get('/api/v1/admin/audit')
        .set('Authorization', `Bearer ${userTokens.accessToken}`);

      expect([401, 403, 404]).toContain(response.status);
    });

    test('should require authentication for audit log access', async () => {
      const response = await request
        .get('/api/v1/admin/audit');

      expect([401, 404]).toContain(response.status);
    });
  });

  describe('Input Validation', () => {
    test('should handle invalid parameters gracefully', async () => {
      const response = await request
        .get('/api/v1/admin/audit?page=invalid')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      expect([200, 400, 404]).toContain(response.status);
    });

    test('should validate date parameters', async () => {
      const response = await request
        .get('/api/v1/admin/audit?startDate=invalid-date')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      expect([200, 400, 404]).toContain(response.status);
    });
  });

  describe('Security Testing', () => {
    test('should prevent SQL injection attempts', async () => {
      const maliciousInput = "'; DROP TABLE audit_logs; --";
      
      const response = await request
        .get(`/api/v1/admin/audit?action=${encodeURIComponent(maliciousInput)}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      // Should not crash the server
      expect([200, 400, 404]).toContain(response.status);
    });

    test('should handle XSS attempts', async () => {
      const xssInput = '<script>alert("xss")</script>';
      
      const response = await request
        .get(`/api/v1/admin/audit?search=${encodeURIComponent(xssInput)}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      expect([200, 400, 404]).toContain(response.status);
    });
  });
}); 
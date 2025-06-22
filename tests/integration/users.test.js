/**
 * User Management Integration Tests
 * Tests user profile management, role assignments, and RBAC functionality
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
  email: 'admin.users@example.com',
  username: 'adminusers',
  password: 'AdminUsers123!',
  firstName: 'Admin',
  lastName: 'Users'
};

const testUser = {
  email: 'user.test@example.com',
  username: 'usertest',
  password: 'UserTest123!',
  firstName: 'User',
  lastName: 'Test'
};

const testModerator = {
  email: 'mod.test@example.com',
  username: 'modtest',
  password: 'ModTest123!',
  firstName: 'Mod',
  lastName: 'Test'
};

describe('User Management Integration Tests', () => {
  let adminTokens = {};
  let userTokens = {};
  let moderatorTokens = {};
  let createdUserId = null;

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

    // Register test moderator
    try {
      const modResponse = await request
        .post('/api/v1/auth/register')
        .send(testModerator);
      
      if (modResponse.status === 201) {
        moderatorTokens = modResponse.body.data.tokens;
      }
    } catch (error) {
      console.log('Failed to register test moderator:', error.message);
    }
  });

  describe('User Profile Management', () => {
    test('should get user profile with valid token', async () => {
      const response = await request
        .get('/api/v1/users/profile')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          user: expect.objectContaining({
            email: testUser.email,
            username: testUser.username,
            firstName: testUser.firstName,
            lastName: testUser.lastName,
            status: expect.any(String),
            createdAt: expect.any(String)
          })
        })
      });
    });

    test('should update user profile successfully', async () => {
      const updateData = {
        firstName: 'Updated',
        lastName: 'Name',
        phone: '+1234567890'
      };

      const response = await request
        .put('/api/v1/users/profile')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          message: 'Profile updated successfully',
          user: expect.objectContaining({
            firstName: updateData.firstName,
            lastName: updateData.lastName,
            phone: updateData.phone
          })
        })
      });
    });

    test('should reject profile update with invalid data', async () => {
      const invalidData = {
        firstName: '', // Empty first name should be invalid
        email: 'invalid-email-format'
      };

      const response = await request
        .put('/api/v1/users/profile')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should require authentication for profile access', async () => {
      const response = await request
        .get('/api/v1/users/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Password Management', () => {
    test('should change password with valid old password', async () => {
      const passwordData = {
        currentPassword: testUser.password,
        newPassword: 'NewPassword123!',
        confirmPassword: 'NewPassword123!'
      };

      const response = await request
        .put('/api/v1/users/password')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(passwordData)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          message: 'Password changed successfully'
        })
      });

      // Update test user password for future tests
      testUser.password = passwordData.newPassword;
    });

    test('should reject password change with wrong current password', async () => {
      const passwordData = {
        currentPassword: 'WrongPassword123!',
        newPassword: 'NewPassword456!',
        confirmPassword: 'NewPassword456!'
      };

      const response = await request
        .put('/api/v1/users/password')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(passwordData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should reject password change with mismatched confirmation', async () => {
      const passwordData = {
        currentPassword: testUser.password,
        newPassword: 'NewPassword456!',
        confirmPassword: 'DifferentPassword456!'
      };

      const response = await request
        .put('/api/v1/users/password')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(passwordData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should reject weak new password', async () => {
      const passwordData = {
        currentPassword: testUser.password,
        newPassword: 'weak',
        confirmPassword: 'weak'
      };

      const response = await request
        .put('/api/v1/users/password')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(passwordData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Admin User Management', () => {
    test('should get all users as admin', async () => {
      const response = await request
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          users: expect.arrayContaining([
            expect.objectContaining({
              email: expect.any(String),
              username: expect.any(String),
              status: expect.any(String)
            })
          ]),
          pagination: expect.objectContaining({
            page: expect.any(Number),
            limit: expect.any(Number),
            total: expect.any(Number)
          })
        })
      });
    });

    test('should create new user as admin', async () => {
      const newUser = {
        email: 'created.user@example.com',
        username: 'createduser',
        password: 'CreatedUser123!',
        firstName: 'Created',
        lastName: 'User',
        role: 'user'
      };

      const response = await request
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send(newUser)
        .expect(201);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          message: 'User created successfully',
          user: expect.objectContaining({
            email: newUser.email,
            username: newUser.username,
            firstName: newUser.firstName,
            lastName: newUser.lastName
          })
        })
      });

      createdUserId = response.body.data.user.id;
    });

    test('should get specific user by ID as admin', async () => {
      if (!createdUserId) {
        // Skip if user creation failed
        return;
      }

      const response = await request
        .get(`/api/v1/admin/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          user: expect.objectContaining({
            id: createdUserId,
            email: 'created.user@example.com',
            username: 'createduser'
          })
        })
      });
    });

    test('should update user as admin', async () => {
      if (!createdUserId) {
        return;
      }

      const updateData = {
        firstName: 'Updated',
        lastName: 'Admin',
        status: 'inactive'
      };

      const response = await request
        .put(`/api/v1/admin/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          message: 'User updated successfully',
          user: expect.objectContaining({
            firstName: updateData.firstName,
            lastName: updateData.lastName,
            status: updateData.status
          })
        })
      });
    });

    test('should delete user as admin', async () => {
      if (!createdUserId) {
        return;
      }

      const response = await request
        .delete(`/api/v1/admin/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          message: 'User deleted successfully'
        })
      });
    });

    test('should reject admin operations for non-admin users', async () => {
      const response = await request
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Insufficient permissions');
    });

    test('should reject admin operations without authentication', async () => {
      const response = await request
        .get('/api/v1/admin/users')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Role Management', () => {
    test('should get available roles', async () => {
      const response = await request
        .get('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          roles: expect.arrayContaining([
            expect.objectContaining({
              name: expect.any(String),
              description: expect.any(String),
              permissions: expect.arrayContaining([expect.any(String)])
            })
          ])
        })
      });
    });

    test('should assign role to user', async () => {
      // Create a test user first
      const testRoleUser = {
        email: 'role.test@example.com',
        username: 'roletest',
        password: 'RoleTest123!',
        firstName: 'Role',
        lastName: 'Test'
      };

      const createResponse = await request
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send(testRoleUser);

      if (createResponse.status === 201) {
        const userId = createResponse.body.data.user.id;

        const response = await request
          .post(`/api/v1/admin/users/${userId}/roles`)
          .set('Authorization', `Bearer ${adminTokens.accessToken}`)
          .send({ role: 'moderator' })
          .expect(200);

        expect(response.body).toEqual({
          success: true,
          data: expect.objectContaining({
            message: 'Role assigned successfully'
          })
        });
      }
    });

    test('should get user permissions', async () => {
      const response = await request
        .get('/api/v1/users/permissions')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          permissions: expect.arrayContaining([expect.any(String)])
        })
      });
    });

    test('should check specific permission', async () => {
      const response = await request
        .get('/api/v1/users/permissions/users:read')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          hasPermission: expect.any(Boolean),
          permission: 'users:read'
        })
      });
    });
  });

  describe('User Activity and Sessions', () => {
    test('should get user activity logs', async () => {
      const response = await request
        .get('/api/v1/users/activity')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          activities: expect.any(Array),
          pagination: expect.objectContaining({
            page: expect.any(Number),
            limit: expect.any(Number)
          })
        })
      });
    });

    test('should get active sessions', async () => {
      const response = await request
        .get('/api/v1/users/sessions')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          sessions: expect.arrayContaining([
            expect.objectContaining({
              id: expect.any(String),
              createdAt: expect.any(String),
              lastActivity: expect.any(String),
              ipAddress: expect.any(String)
            })
          ])
        })
      });
    });

    test('should revoke specific session', async () => {
      // First get sessions to get a session ID
      const sessionsResponse = await request
        .get('/api/v1/users/sessions')
        .set('Authorization', `Bearer ${userTokens.accessToken}`);

      if (sessionsResponse.body.data.sessions.length > 0) {
        const sessionId = sessionsResponse.body.data.sessions[0].id;

        const response = await request
          .delete(`/api/v1/users/sessions/${sessionId}`)
          .set('Authorization', `Bearer ${userTokens.accessToken}`)
          .expect(200);

        expect(response.body).toEqual({
          success: true,
          data: expect.objectContaining({
            message: 'Session revoked successfully'
          })
        });
      }
    });
  });

  describe('Input Validation and Security', () => {
    test('should validate user ID format in admin endpoints', async () => {
      const response = await request
        .get('/api/v1/admin/users/invalid-uuid')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should prevent SQL injection in user queries', async () => {
      const maliciousQuery = "'; DROP TABLE users; --";
      
      const response = await request
        .get(`/api/v1/admin/users?search=${encodeURIComponent(maliciousQuery)}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      // Should return empty results, not error
      expect(response.body.success).toBe(true);
    });

    test('should sanitize XSS attempts in user updates', async () => {
      const xssData = {
        firstName: '<script>alert("xss")</script>',
        lastName: '<img src="x" onerror="alert(1)">'
      };

      const response = await request
        .put('/api/v1/users/profile')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send(xssData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should enforce rate limiting on profile updates', async () => {
      const promises = [];
      
      // Make multiple rapid updates
      for (let i = 0; i < 15; i++) {
        promises.push(
          request
            .put('/api/v1/users/profile')
            .set('Authorization', `Bearer ${userTokens.accessToken}`)
            .send({ firstName: `Test${i}` })
        );
      }

      const responses = await Promise.all(promises);
      
      // Should have some rate limited responses
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('Pagination and Filtering', () => {
    test('should support pagination in user list', async () => {
      const response = await request
        .get('/api/v1/admin/users?page=1&limit=5')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body.data.pagination).toEqual(
        expect.objectContaining({
          page: 1,
          limit: 5,
          total: expect.any(Number),
          pages: expect.any(Number)
        })
      );
    });

    test('should support filtering users by status', async () => {
      const response = await request
        .get('/api/v1/admin/users?status=active')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      if (response.body.data.users.length > 0) {
        response.body.data.users.forEach(user => {
          expect(user.status).toBe('active');
        });
      }
    });

    test('should support searching users by email or username', async () => {
      const response = await request
        .get(`/api/v1/admin/users?search=${testUser.username}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });
}); 
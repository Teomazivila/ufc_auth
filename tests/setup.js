/**
 * Jest Test Setup
 * Configures the test environment for UFC Auth API
 */

import { jest } from '@jest/globals';

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key';
process.env.DB_HOST = 'localhost';
process.env.DB_PORT = '5432';
process.env.DB_NAME = 'ufc_auth_test';
process.env.DB_USER = 'postgres';
process.env.DB_PASSWORD = 'postgres123';
process.env.REDIS_HOST = 'localhost';
process.env.REDIS_PORT = '6379';
process.env.EMAIL_HOST = 'localhost';
process.env.EMAIL_PORT = '1025';

// Increase timeout for database operations
jest.setTimeout(30000);

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Global test utilities
global.testUtils = {
  // Helper to create test user data
  createTestUser: (overrides = {}) => ({
    email: 'test@example.com',
    username: 'testuser',
    password: 'TestPass123!',
    confirmPassword: 'TestPass123!',
    firstName: 'Test',
    lastName: 'User',
    acceptTerms: true,
    ...overrides,
  }),

  // Helper to create admin user data
  createAdminUser: (overrides = {}) => ({
    email: 'admin@example.com',
    username: 'adminuser',
    password: 'AdminPass123!',
    confirmPassword: 'AdminPass123!',
    firstName: 'Admin',
    lastName: 'User',
    acceptTerms: true,
    ...overrides,
  }),

  // Helper to create audit log data
  createAuditLogData: (overrides = {}) => ({
    user_id: '123e4567-e89b-12d3-a456-426614174000',
    action: 'LOGIN_SUCCESS',
    resource: 'auth',
    ip_address: '127.0.0.1',
    user_agent: 'Jest Test Agent',
    success: true,
    details: { test: true },
    ...overrides,
  }),
};

// Setup and teardown hooks
beforeAll(async () => {
  // Global setup if needed
});

afterAll(async () => {
  // Global cleanup if needed
});

beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

afterEach(() => {
  // Cleanup after each test
}); 
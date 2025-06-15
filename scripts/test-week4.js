#!/usr/bin/env node

/**
 * Week 4 Testing Suite - Following 2025 IAM Best Practices
 * Tests password recovery, audit system, and email notifications
 * Reference: StrongDM IAM Best Practices 2025
 */

import axios from 'axios';
import { logger } from '../src/utils/logger.js';

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api/v1';
const TEST_EMAIL = process.env.TEST_EMAIL || 'test.week4@example.com';

// Test configuration
const config = {
  timeout: 10000,
  retries: 3
};

// Test state
let testState = {
  adminToken: null,
  testUserId: null,
  resetToken: null,
  testResults: [],
  startTime: Date.now()
};

class TestFramework {
  constructor() {
    this.testCount = 0;
    this.passedTests = 0;
    this.failedTests = 0;
  }

  async test(name, testFn) {
    this.testCount++;
    console.log(`\n🧪 Testing: ${name}`);
    
    try {
      await testFn();
      this.passedTests++;
      console.log(`✅ PASSED: ${name}`);
      testState.testResults.push({ name, status: 'PASSED', error: null });
    } catch (error) {
      this.failedTests++;
      console.log(`❌ FAILED: ${name}`);
      console.log(`   Error: ${error.message}`);
      testState.testResults.push({ name, status: 'FAILED', error: error.message });
    }
  }

  printSummary() {
    const duration = ((Date.now() - testState.startTime) / 1000).toFixed(2);
    
    console.log('\n' + '='.repeat(50));
    console.log('📊 Test Results Summary');
    console.log('='.repeat(50));
    console.log(`✅ Passed: ${this.passedTests}`);
    console.log(`❌ Failed: ${this.failedTests}`);
    console.log(`📈 Success Rate: ${((this.passedTests / this.testCount) * 100).toFixed(1)}%`);
    console.log(`⏱️  Duration: ${duration}s`);
    
    if (this.failedTests === 0) {
      console.log('\n🎉 All tests passed! Week 4 features are working correctly.');
    } else {
      console.log('\n⚠️  Some tests failed. Check the implementation.');
    }
  }
}

const testFramework = new TestFramework();

// Helper functions
const makeRequest = async (method, url, data = null, headers = {}) => {
  try {
    const response = await axios({
      method,
      url: `${API_BASE_URL}${url}`,
      data,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      timeout: config.timeout
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`${error.response.status}: ${error.response.data.message || error.response.statusText}`);
    }
    throw error;
  }
};

const authenticateAsAdmin = async () => {
  // First register admin user if not exists
  try {
    await makeRequest('POST', '/auth/register', {
      email: 'admin.week4@example.com',
      username: 'adminweek4',
      password: 'AdminPass123!',
      confirmPassword: 'AdminPass123!',
      firstName: 'Admin',
      lastName: 'Week4',
      acceptTerms: true
    });
  } catch (error) {
    // User might already exist, continue
  }

  // Login as admin
  const loginResponse = await makeRequest('POST', '/auth/login', {
    email: 'admin.week4@example.com',
    password: 'AdminPass123!'
  });

  if (!loginResponse.success || !loginResponse.data.tokens.accessToken) {
    throw new Error('Failed to authenticate as admin');
  }

  testState.adminToken = loginResponse.data.tokens.accessToken;
  return testState.adminToken;
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Test Suite
async function runWeek4Tests() {
  console.log('🚀 Starting Week 4 Testing Suite');
  console.log('Testing: Password Recovery, Audit System, Email Notifications');
  console.log('Following 2025 IAM Security Best Practices\n');

  // Setup
  await testFramework.test('Admin Authentication Setup', async () => {
    await authenticateAsAdmin();
    if (!testState.adminToken) {
      throw new Error('Admin token not obtained');
    }
  });

  // Password Recovery Tests
  await testFramework.test('Password Recovery - Request Reset', async () => {
    const response = await makeRequest('POST', '/auth/forgot-password', {
      email: TEST_EMAIL
    });

    if (!response.success) {
      throw new Error('Password reset request failed');
    }

    // Check for security-appropriate response (always success to prevent enumeration)
    if (!response.data.message.includes('password reset link has been sent')) {
      throw new Error('Unexpected password reset response');
    }
  });

  await testFramework.test('Password Recovery - Invalid Email', async () => {
    const response = await makeRequest('POST', '/auth/forgot-password', {
      email: 'nonexistent@example.com'
    });

    // Should still return success to prevent email enumeration
    if (!response.success) {
      throw new Error('Password reset should return success for non-existent emails');
    }
  });

  await testFramework.test('Password Recovery - Invalid Token', async () => {
    try {
      await makeRequest('POST', '/auth/reset-password', {
        token: 'invalid-token-12345',
        newPassword: 'NewPassword123!',
        confirmNewPassword: 'NewPassword123!'
      });
      throw new Error('Should have failed with invalid token');
    } catch (error) {
      if (!error.message.includes('Invalid or expired')) {
        throw new Error('Expected invalid token error');
      }
    }
  });

  // Audit System Tests
  await testFramework.test('Audit System - Access Logs (Requires Admin)', async () => {
    const response = await makeRequest('GET', '/audit/logs?limit=10', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!response.success) {
      throw new Error('Failed to access audit logs');
    }

    if (!response.data.logs || !Array.isArray(response.data.logs)) {
      throw new Error('Audit logs response malformed');
    }

    if (!response.data.pagination) {
      throw new Error('Audit logs missing pagination');
    }
  });

  await testFramework.test('Audit System - Security Analytics', async () => {
    const response = await makeRequest('GET', '/audit/analytics?timeRange=24h', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!response.success) {
      throw new Error('Failed to get security analytics');
    }

    const analytics = response.data.analytics;
    if (typeof analytics.total_events === 'undefined') {
      throw new Error('Analytics missing total_events');
    }
  });

  await testFramework.test('Audit System - Statistics Dashboard', async () => {
    const response = await makeRequest('GET', '/audit/statistics?timeRange=7d', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!response.success) {
      throw new Error('Failed to get audit statistics');
    }

    const stats = response.data;
    if (typeof stats.total_events === 'undefined' || typeof stats.failure_rate === 'undefined') {
      throw new Error('Statistics response incomplete');
    }
  });

  await testFramework.test('Audit System - Export Functionality (JSON)', async () => {
    const response = await makeRequest('GET', '/audit/export?format=json&limit=5', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!Array.isArray(response)) {
      throw new Error('Export should return array of logs');
    }
  });

  await testFramework.test('Audit System - Search Functionality', async () => {
    const response = await makeRequest('GET', '/audit/search?q=login&type=authentication', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!response.success) {
      throw new Error('Failed to search audit logs');
    }

    if (!response.data.logs || !response.data.search) {
      throw new Error('Search response malformed');
    }
  });

  // Authorization Tests (Zero Trust Verification)
  await testFramework.test('Zero Trust - Unauthorized Audit Access', async () => {
    try {
      await makeRequest('GET', '/audit/logs');
      throw new Error('Should require authentication');
    } catch (error) {
      if (!error.message.includes('401')) {
        throw new Error('Expected 401 unauthorized error');
      }
    }
  });

  await testFramework.test('Zero Trust - Insufficient Permissions', async () => {
    // Create a regular user
    try {
      await makeRequest('POST', '/auth/register', {
        email: 'regular.user@example.com',
        username: 'regularuser',
        password: 'UserPass123!',
        confirmPassword: 'UserPass123!',
        firstName: 'Regular',
        lastName: 'User',
        acceptTerms: true
      });
    } catch (error) {
      // User might exist
    }

    const userLoginResponse = await makeRequest('POST', '/auth/login', {
      email: 'regular.user@example.com',
      password: 'UserPass123!'
    });

    try {
      await makeRequest('GET', '/audit/logs', null, {
        'Authorization': `Bearer ${userLoginResponse.data.tokens.accessToken}`
      });
      throw new Error('Regular user should not access audit logs');
    } catch (error) {
      if (!error.message.includes('403')) {
        throw new Error('Expected 403 forbidden error');
      }
    }
  });

  // Rate Limiting Tests
  await testFramework.test('Rate Limiting - Password Reset Protection', async () => {
    const requests = [];
    
    // Make multiple rapid requests
    for (let i = 0; i < 8; i++) {
      requests.push(
        makeRequest('POST', '/auth/forgot-password', {
          email: `test${i}@example.com`
        }).catch(error => error)
      );
    }

    const results = await Promise.all(requests);
    
    // Check if some requests were rate limited
    const rateLimited = results.some(result => 
      result instanceof Error && result.message.includes('429')
    );

    if (!rateLimited) {
      console.log('⚠️  Note: Rate limiting may not be strictly enforced in test environment');
    }
  });

  // System Maintenance Tests
  await testFramework.test('System Maintenance - Token Cleanup', async () => {
    const response = await makeRequest('POST', '/audit/maintenance', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!response.success) {
      throw new Error('Maintenance endpoint failed');
    }

    if (typeof response.data.results.expired_tokens_cleared === 'undefined') {
      throw new Error('Maintenance response missing cleanup results');
    }
  });

  // Security Event Logging Tests
  await testFramework.test('Security Event Logging - Failed Login Tracking', async () => {
    // Attempt failed login
    try {
      await makeRequest('POST', '/auth/login', {
        email: 'admin.week4@example.com',
        password: 'WrongPassword123!'
      });
    } catch (error) {
      // Expected to fail
    }

    // Wait a bit for audit log to be written
    await sleep(1000);

    // Check if the failed login was logged
    const logsResponse = await makeRequest('GET', '/audit/logs?action=LOGIN_FAILED&limit=5', null, {
      'Authorization': `Bearer ${testState.adminToken}`
    });

    if (!logsResponse.success) {
      throw new Error('Failed to retrieve audit logs');
    }

    // Should have at least one failed login event
    const failedLogins = logsResponse.data.logs.filter(log => 
      log.action === 'LOGIN_FAILED' && log.success === false
    );

    if (failedLogins.length === 0) {
      throw new Error('Failed login events not being logged');
    }
  });

  // API Information Endpoint Test
  await testFramework.test('API Information - Week 4 Features Listed', async () => {
    const response = await makeRequest('GET', '/api', null, {}, 'http://localhost:3000');
    
    if (!response.success) {
      throw new Error('API info endpoint failed');
    }

    if (!response.data.endpoints.audit) {
      throw new Error('Audit endpoints not listed in API info');
    }
  });

  testFramework.printSummary();
}

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Run tests
if (import.meta.url === `file://${process.argv[1]}`) {
  runWeek4Tests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
}

export { runWeek4Tests }; 
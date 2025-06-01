#!/usr/bin/env node

/**
 * Week 2 Testing Script - Authentication Features
 * Following 2025 best practices for Node.js 20+ testing
 */

import { config } from '../src/config/index.js';

const API_BASE = `http://localhost:${config.port}/api/v1`;
const HEALTH_BASE = `http://localhost:${config.port}`;

/**
 * Test utilities
 */
class TestRunner {
  constructor() {
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
    this.accessToken = null;
    this.refreshToken = null;
    this.testUser = {
      email: 'test@example.com',
      username: 'testuser',
      password: 'TestPass123!',
      confirmPassword: 'TestPass123!',
      firstName: 'Test',
      lastName: 'User',
      acceptTerms: true
    };
  }

  async request(method, url, data = null, headers = {}) {
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };

    if (data) {
      options.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, options);
      const result = await response.json();
      
      return {
        status: response.status,
        data: result,
        headers: Object.fromEntries(response.headers.entries())
      };
    } catch (error) {
      return {
        status: 0,
        error: error.message
      };
    }
  }

  async test(name, testFn) {
    try {
      console.log(`\n🧪 Testing: ${name}`);
      await testFn();
      console.log(`✅ PASSED: ${name}`);
      this.passed++;
    } catch (error) {
      console.log(`❌ FAILED: ${name}`);
      console.log(`   Error: ${error.message}`);
      this.failed++;
    }
  }

  assert(condition, message) {
    if (!condition) {
      throw new Error(message);
    }
  }

  async runAll() {
    console.log('🚀 Starting Week 2 Authentication Tests\n');
    console.log('=' .repeat(50));

    // Health checks first
    await this.test('Health Check - Basic', async () => {
      const response = await this.request('GET', `${HEALTH_BASE}/health`);
      this.assert(response.status === 200, 'Health check should return 200');
      this.assert(response.data.success === true, 'Health check should be successful');
    });

    await this.test('Health Check - Detailed', async () => {
      const response = await this.request('GET', `${HEALTH_BASE}/health/detailed`);
      this.assert(response.status === 200, 'Detailed health check should return 200');
      this.assert(response.data.data.database.connected === true, 'Database should be connected');
      this.assert(response.data.data.redis.connected === true, 'Redis should be connected');
    });

    // API Info
    await this.test('API Information', async () => {
      const response = await this.request('GET', `${API_BASE.replace('/v1', '')}`);
      this.assert(response.status === 200, 'API info should return 200');
      this.assert(response.data.data.name === 'UFC Auth API', 'API name should match');
    });

    // Authentication Tests
    await this.test('User Registration', async () => {
      const response = await this.request('POST', `${API_BASE}/auth/register`, this.testUser);
      this.assert(response.status === 201, 'Registration should return 201');
      this.assert(response.data.success === true, 'Registration should be successful');
      this.assert(response.data.data.user.email === this.testUser.email, 'User email should match');
      this.assert(response.data.data.tokens.accessToken, 'Should return access token');
      this.assert(response.data.data.tokens.refreshToken, 'Should return refresh token');
      
      // Store tokens for subsequent tests
      this.accessToken = response.data.data.tokens.accessToken;
      this.refreshToken = response.data.data.tokens.refreshToken;
    });

    await this.test('Duplicate Registration Prevention', async () => {
      const response = await this.request('POST', `${API_BASE}/auth/register`, this.testUser);
      this.assert(response.status === 409, 'Duplicate registration should return 409');
      this.assert(response.data.success === false, 'Duplicate registration should fail');
    });

    await this.test('Registration Validation - Invalid Email', async () => {
      const invalidUser = { ...this.testUser, email: 'invalid-email' };
      const response = await this.request('POST', `${API_BASE}/auth/register`, invalidUser);
      this.assert(response.status === 400, 'Invalid email should return 400');
      this.assert(response.data.error.code === 'VALIDATION_ERROR', 'Should be validation error');
    });

    await this.test('Registration Validation - Weak Password', async () => {
      const weakPasswordUser = { 
        ...this.testUser, 
        email: 'weak@example.com',
        password: '123',
        confirmPassword: '123'
      };
      const response = await this.request('POST', `${API_BASE}/auth/register`, weakPasswordUser);
      this.assert(response.status === 400, 'Weak password should return 400');
    });

    await this.test('User Login', async () => {
      const loginData = {
        email: this.testUser.email,
        password: this.testUser.password
      };
      const response = await this.request('POST', `${API_BASE}/auth/login`, loginData);
      this.assert(response.status === 200, 'Login should return 200');
      this.assert(response.data.success === true, 'Login should be successful');
      this.assert(response.data.data.tokens.accessToken, 'Should return access token');
    });

    await this.test('Login - Invalid Credentials', async () => {
      const invalidLogin = {
        email: this.testUser.email,
        password: 'wrongpassword'
      };
      const response = await this.request('POST', `${API_BASE}/auth/login`, invalidLogin);
      this.assert(response.status === 401, 'Invalid login should return 401');
      this.assert(response.data.success === false, 'Invalid login should fail');
    });

    await this.test('Get Current User Profile', async () => {
      const response = await this.request('GET', `${API_BASE}/auth/me`, null, {
        'Authorization': `Bearer ${this.accessToken}`
      });
      this.assert(response.status === 200, 'Profile request should return 200');
      this.assert(response.data.data.user.email === this.testUser.email, 'Profile email should match');
    });

    await this.test('Authentication Status Check', async () => {
      const response = await this.request('GET', `${API_BASE}/auth/status`, null, {
        'Authorization': `Bearer ${this.accessToken}`
      });
      this.assert(response.status === 200, 'Status check should return 200');
      this.assert(response.data.data.authenticated === true, 'Should be authenticated');
      this.assert(response.data.data.tokenValid === true, 'Token should be valid');
    });

    await this.test('Token Refresh', async () => {
      const response = await this.request('POST', `${API_BASE}/auth/refresh`, {
        refreshToken: this.refreshToken
      });
      this.assert(response.status === 200, 'Token refresh should return 200');
      this.assert(response.data.data.accessToken, 'Should return new access token');
      
      // Update access token
      this.accessToken = response.data.data.accessToken;
    });

    await this.test('2FA Setup Initiation', async () => {
      const response = await this.request('POST', `${API_BASE}/auth/2fa/setup`, null, {
        'Authorization': `Bearer ${this.accessToken}`
      });
      this.assert(response.status === 200, '2FA setup should return 200');
      this.assert(response.data.data.qrCode, 'Should return QR code');
      this.assert(response.data.data.manualEntryKey, 'Should return manual entry key');
    });

    await this.test('Unauthorized Access Protection', async () => {
      const response = await this.request('GET', `${API_BASE}/auth/me`);
      this.assert(response.status === 401, 'Unauthorized request should return 401');
    });

    await this.test('Invalid Token Protection', async () => {
      const response = await this.request('GET', `${API_BASE}/auth/me`, null, {
        'Authorization': 'Bearer invalid-token'
      });
      this.assert(response.status === 401, 'Invalid token should return 401');
    });

    await this.test('User Logout', async () => {
      const response = await this.request('POST', `${API_BASE}/auth/logout`, {
        refreshToken: this.refreshToken
      }, {
        'Authorization': `Bearer ${this.accessToken}`
      });
      this.assert(response.status === 200, 'Logout should return 200');
      this.assert(response.data.success === true, 'Logout should be successful');
    });

    await this.test('Access After Logout', async () => {
      const response = await this.request('GET', `${API_BASE}/auth/me`, null, {
        'Authorization': `Bearer ${this.accessToken}`
      });
      this.assert(response.status === 401, 'Access after logout should return 401');
    });

    // Rate limiting tests
    await this.test('Rate Limiting Protection', async () => {
      const promises = [];
      // Make multiple rapid requests to trigger rate limiting
      for (let i = 0; i < 25; i++) {
        promises.push(this.request('POST', `${API_BASE}/auth/login`, {
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        }));
      }
      
      const responses = await Promise.all(promises);
      const rateLimited = responses.some(r => r.status === 429);
      this.assert(rateLimited, 'Should trigger rate limiting after multiple requests');
    });

    // Summary
    console.log('\n' + '=' .repeat(50));
    console.log('📊 Test Results Summary');
    console.log('=' .repeat(50));
    console.log(`✅ Passed: ${this.passed}`);
    console.log(`❌ Failed: ${this.failed}`);
    console.log(`📈 Success Rate: ${((this.passed / (this.passed + this.failed)) * 100).toFixed(1)}%`);

    if (this.failed === 0) {
      console.log('\n🎉 All tests passed! Week 2 authentication features are working correctly.');
    } else {
      console.log('\n⚠️  Some tests failed. Please check the implementation.');
      process.exit(1);
    }
  }
}

/**
 * Main execution
 */
async function main() {
  // Check if server is running
  try {
    const response = await fetch(`${HEALTH_BASE}/health`);
    if (!response.ok) {
      throw new Error('Server not responding');
    }
  } catch (error) {
    console.error('❌ Server is not running. Please start the server first:');
    console.error('   docker compose up --build');
    process.exit(1);
  }

  const runner = new TestRunner();
  await runner.runAll();
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run tests
main().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
}); 
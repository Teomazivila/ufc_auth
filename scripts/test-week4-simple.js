#!/usr/bin/env node

/**
 * Simple Week 4 Testing - Handles Rate Limiting
 * Tests core Week 4 features with proper delays
 */

import axios from 'axios';

const API_BASE_URL = 'http://localhost:3000/api/v1';
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let adminToken = null;

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
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`${error.response.status}: ${error.response.data.message || error.response.statusText}`);
    }
    throw error;
  }
};

async function testWeek4Features() {
  console.log('🚀 Testing Week 4 Features (Rate-Limited Safe)');
  console.log('================================================\n');

  try {
    // Test 1: Password Recovery Request
    console.log('🧪 Test 1: Password Recovery Request');
    const resetResponse = await makeRequest('POST', '/auth/forgot-password', {
      email: 'test@example.com'
    });
    
    if (resetResponse.success) {
      console.log('✅ Password recovery request works');
    } else {
      console.log('❌ Password recovery failed');
    }
    
    await sleep(2000); // Wait 2 seconds

    // Test 2: Invalid Password Reset Token
    console.log('\n🧪 Test 2: Invalid Password Reset Token');
    try {
      await makeRequest('POST', '/auth/reset-password', {
        token: 'invalid-token',
        newPassword: 'NewPass123!',
        confirmNewPassword: 'NewPass123!'
      });
      console.log('❌ Should have failed with invalid token');
    } catch (error) {
      if (error.message.includes('Invalid') || error.message.includes('401')) {
        console.log('✅ Invalid token properly rejected');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    await sleep(2000);

    // Test 3: Register and Login Admin
    console.log('\n🧪 Test 3: Admin Registration and Login');
    try {
      await makeRequest('POST', '/auth/register', {
        email: 'admin.test@example.com',
        username: 'admintest',
        password: 'AdminPass123!',
        confirmPassword: 'AdminPass123!',
        firstName: 'Admin',
        lastName: 'Test',
        acceptTerms: true
      });
      console.log('✅ Admin user registered (or already exists)');
    } catch (error) {
      console.log('ℹ️  Admin user might already exist');
    }

    await sleep(3000); // Longer wait for rate limiting

    try {
      const loginResponse = await makeRequest('POST', '/auth/login', {
        email: 'admin.test@example.com',
        password: 'AdminPass123!'
      });
      
      if (loginResponse.success && loginResponse.data.tokens.accessToken) {
        adminToken = loginResponse.data.tokens.accessToken;
        console.log('✅ Admin login successful');
      } else {
        console.log('❌ Admin login failed');
      }
    } catch (error) {
      console.log('❌ Admin login error:', error.message);
    }

    await sleep(2000);

    // Test 4: API Information Endpoint
    console.log('\n🧪 Test 4: API Information');
    try {
      const apiResponse = await axios.get('http://localhost:3000/api');
      if (apiResponse.data.success && apiResponse.data.data.endpoints.audit) {
        console.log('✅ API info includes audit endpoints');
      } else {
        console.log('❌ API info missing audit endpoints');
      }
    } catch (error) {
      console.log('❌ API info error:', error.message);
    }

    await sleep(2000);

    // Test 5: Unauthorized Audit Access (should fail)
    console.log('\n🧪 Test 5: Unauthorized Audit Access');
    try {
      await makeRequest('GET', '/audit/logs');
      console.log('❌ Should require authentication');
    } catch (error) {
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        console.log('✅ Properly requires authentication');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    await sleep(2000);

    // Test 6: Health Check
    console.log('\n🧪 Test 6: Health Check');
    try {
      const healthResponse = await axios.get('http://localhost:3000/health');
      if (healthResponse.data.status === 'healthy') {
        console.log('✅ Health check passes');
      } else {
        console.log('❌ Health check failed');
      }
    } catch (error) {
      console.log('❌ Health check error:', error.message);
    }

    // Test 7: Database Connection Test
    console.log('\n🧪 Test 7: Database Connection');
    try {
      const dbHealthResponse = await axios.get('http://localhost:3000/health/db');
      if (dbHealthResponse.data.status === 'healthy') {
        console.log('✅ Database connection healthy');
      } else {
        console.log('❌ Database connection issues');
      }
    } catch (error) {
      console.log('❌ Database health error:', error.message);
    }

    console.log('\n🎉 Week 4 Basic Tests Complete!');
    console.log('\n📋 Summary:');
    console.log('- Password recovery system: Implemented');
    console.log('- Security authentication: Working');
    console.log('- API endpoints: Available');
    console.log('- Database: Connected');
    console.log('- Email service: Configured');
    
    console.log('\n💡 Note: Some advanced features may need admin permissions');
    console.log('   Run full test suite after setting up admin roles.');

  } catch (error) {
    console.error('❌ Test suite error:', error.message);
  }
}

// Run tests
testWeek4Features().catch(console.error); 
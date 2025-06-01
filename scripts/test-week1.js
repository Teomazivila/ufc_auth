#!/usr/bin/env node

/**
 * Test script for Week 1 implementation
 * Tests basic server functionality and health endpoints
 */

import { config } from '../src/config/index.js';
import { logger } from '../src/utils/logger.js';
import { connectDatabase } from '../src/config/database.js';
import { connectRedis } from '../src/config/redis.js';

const TEST_BASE_URL = `http://localhost:${config.port}`;

/**
 * Make HTTP request
 */
async function makeRequest(url, options = {}) {
  try {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    });
    
    const data = await response.json();
    return { status: response.status, data, ok: response.ok };
  } catch (error) {
    return { status: 0, error: error.message, ok: false };
  }
}

/**
 * Test database connection
 */
async function testDatabase() {
  console.log('\n🔍 Testing database connection...');
  try {
    await connectDatabase();
    console.log('✅ Database connection successful');
    return true;
  } catch (error) {
    console.log('❌ Database connection failed:', error.message);
    return false;
  }
}

/**
 * Test Redis connection
 */
async function testRedis() {
  console.log('\n🔍 Testing Redis connection...');
  try {
    await connectRedis();
    console.log('✅ Redis connection successful');
    return true;
  } catch (error) {
    console.log('❌ Redis connection failed:', error.message);
    return false;
  }
}

/**
 * Test health endpoints
 */
async function testHealthEndpoints() {
  console.log('\n🔍 Testing health endpoints...');
  
  const endpoints = [
    { path: '/health', name: 'Basic Health Check' },
    { path: '/health/detailed', name: 'Detailed Health Check' },
    { path: '/health/database', name: 'Database Health Check' },
    { path: '/health/redis', name: 'Redis Health Check' },
    { path: '/health/ready', name: 'Readiness Probe' },
    { path: '/health/live', name: 'Liveness Probe' },
    { path: '/health/startup', name: 'Startup Probe' },
    { path: '/health/metrics', name: 'System Metrics' }
  ];
  
  const results = [];
  
  for (const endpoint of endpoints) {
    const result = await makeRequest(`${TEST_BASE_URL}${endpoint.path}`);
    const status = result.ok ? '✅' : '❌';
    console.log(`${status} ${endpoint.name}: ${result.status}`);
    
    if (result.data) {
      console.log(`   Response: ${JSON.stringify(result.data, null, 2).substring(0, 100)}...`);
    }
    
    results.push({ ...endpoint, ...result });
  }
  
  return results;
}

/**
 * Test API info endpoint
 */
async function testApiInfo() {
  console.log('\n🔍 Testing API info endpoint...');
  
  const result = await makeRequest(`${TEST_BASE_URL}/api`);
  const status = result.ok ? '✅' : '❌';
  console.log(`${status} API Info: ${result.status}`);
  
  if (result.data) {
    console.log(`   API Name: ${result.data.data?.name}`);
    console.log(`   Version: ${result.data.data?.version}`);
    console.log(`   Environment: ${result.data.data?.environment}`);
  }
  
  return result;
}

/**
 * Test 404 handling
 */
async function test404Handling() {
  console.log('\n🔍 Testing 404 handling...');
  
  const result = await makeRequest(`${TEST_BASE_URL}/nonexistent-route`);
  const status = result.status === 404 ? '✅' : '❌';
  console.log(`${status} 404 Handling: ${result.status}`);
  
  if (result.data) {
    console.log(`   Error Code: ${result.data.error?.code}`);
    console.log(`   Error Message: ${result.data.error?.message}`);
  }
  
  return result;
}

/**
 * Wait for server to be ready
 */
async function waitForServer(maxAttempts = 30, delay = 1000) {
  console.log('\n⏳ Waiting for server to be ready...');
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const result = await makeRequest(`${TEST_BASE_URL}/health`);
      if (result.ok) {
        console.log(`✅ Server is ready (attempt ${attempt})`);
        return true;
      }
    } catch (error) {
      // Server not ready yet
    }
    
    console.log(`   Attempt ${attempt}/${maxAttempts} - waiting...`);
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  
  console.log('❌ Server failed to start within timeout');
  return false;
}

/**
 * Run all tests
 */
async function runTests() {
  console.log('🚀 Starting Week 1 Implementation Tests');
  console.log('=====================================');
  
  const results = {
    database: false,
    redis: false,
    server: false,
    health: [],
    apiInfo: null,
    notFound: null
  };
  
  try {
    // Test infrastructure connections
    results.database = await testDatabase();
    results.redis = await testRedis();
    
    // Wait for server to be ready
    results.server = await waitForServer();
    
    if (results.server) {
      // Test endpoints
      results.health = await testHealthEndpoints();
      results.apiInfo = await testApiInfo();
      results.notFound = await test404Handling();
    }
    
    // Summary
    console.log('\n📊 Test Summary');
    console.log('===============');
    console.log(`Database Connection: ${results.database ? '✅' : '❌'}`);
    console.log(`Redis Connection: ${results.redis ? '✅' : '❌'}`);
    console.log(`Server Ready: ${results.server ? '✅' : '❌'}`);
    
    if (results.server) {
      const healthPassed = results.health.filter(h => h.ok).length;
      const healthTotal = results.health.length;
      console.log(`Health Endpoints: ${healthPassed}/${healthTotal} passed`);
      console.log(`API Info Endpoint: ${results.apiInfo?.ok ? '✅' : '❌'}`);
      console.log(`404 Handling: ${results.notFound?.status === 404 ? '✅' : '❌'}`);
    }
    
    const allPassed = results.database && results.redis && results.server &&
                     results.health.every(h => h.ok) &&
                     results.apiInfo?.ok &&
                     results.notFound?.status === 404;
    
    console.log(`\n🎯 Overall Result: ${allPassed ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
    
    if (allPassed) {
      console.log('\n🎉 Week 1 implementation is working correctly!');
      console.log('✨ Ready to proceed with authentication implementation.');
    } else {
      console.log('\n⚠️  Some issues found. Please check the logs above.');
    }
    
    return allPassed;
    
  } catch (error) {
    console.error('\n💥 Test execution failed:', error);
    logger.error('Test execution failed:', error);
    return false;
  }
}

// Run tests if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Test runner failed:', error);
      process.exit(1);
    });
}

export { runTests }; 
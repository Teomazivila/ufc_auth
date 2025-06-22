/**
 * Test Server Helper
 * Provides utilities for managing server lifecycle during integration tests
 */

import Server from '../../src/server.js';

let serverInstance = null;

export const startTestServer = async () => {
  if (serverInstance) {
    return serverInstance;
  }

  try {
    const server = new Server();
    serverInstance = server.app;
    
    // Wait for server to be ready
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    return serverInstance;
  } catch (error) {
    console.error('Failed to start test server:', error);
    throw error;
  }
};

export const stopTestServer = async () => {
  if (serverInstance) {
    // In a real scenario, you might want to properly close the server
    serverInstance = null;
  }
};

export const getTestServer = () => {
  if (!serverInstance) {
    throw new Error('Test server not started. Call startTestServer() first.');
  }
  return serverInstance;
};

export default {
  startTestServer,
  stopTestServer,
  getTestServer
}; 
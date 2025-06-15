#!/usr/bin/env node

/**
 * Comprehensive Test Runner for UFC Auth API
 * Runs unit tests, integration tests, and generates coverage reports
 */

import { spawn } from 'child_process';
import { existsSync } from 'fs';
import path from 'path';

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(message) {
  log(`\n${'='.repeat(60)}`, colors.cyan);
  log(`${message}`, colors.cyan + colors.bright);
  log(`${'='.repeat(60)}`, colors.cyan);
}

function logSection(message) {
  log(`\n${'-'.repeat(40)}`, colors.blue);
  log(`${message}`, colors.blue + colors.bright);
  log(`${'-'.repeat(40)}`, colors.blue);
}

async function runCommand(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    log(`Running: ${command} ${args.join(' ')}`, colors.yellow);
    
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: true,
      ...options,
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve(code);
      } else {
        reject(new Error(`Command failed with exit code ${code}`));
      }
    });

    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function checkPrerequisites() {
  logSection('Checking Prerequisites');
  
  // Check if Jest is installed
  try {
    await runCommand('npx', ['jest', '--version'], { stdio: 'pipe' });
    log('✓ Jest is available', colors.green);
  } catch (error) {
    log('✗ Jest is not available', colors.red);
    throw new Error('Jest is required for running tests');
  }

  // Check if test files exist
  const testDirs = ['tests/unit', 'tests/integration'];
  for (const dir of testDirs) {
    if (existsSync(dir)) {
      log(`✓ ${dir} directory exists`, colors.green);
    } else {
      log(`✗ ${dir} directory not found`, colors.red);
    }
  }

  // Check if setup file exists
  if (existsSync('tests/setup.js')) {
    log('✓ Test setup file exists', colors.green);
  } else {
    log('✗ Test setup file not found', colors.red);
  }
}

async function runUnitTests() {
  logSection('Running Unit Tests');
  
  try {
    await runCommand('npx', [
      'jest',
      'tests/unit',
      '--verbose',
      '--colors',
      '--detectOpenHandles',
      '--forceExit',
    ], { 
      env: { 
        ...process.env, 
        NODE_OPTIONS: '--experimental-vm-modules' 
      } 
    });
    log('✓ Unit tests completed successfully', colors.green);
    return true;
  } catch (error) {
    log('✗ Unit tests failed', colors.red);
    return false;
  }
}

async function runIntegrationTests() {
  logSection('Running Integration Tests');
  
  try {
    await runCommand('npx', [
      'jest',
      'tests/integration',
      '--verbose',
      '--colors',
      '--detectOpenHandles',
      '--forceExit',
      '--runInBand', // Run integration tests sequentially
    ], { 
      env: { 
        ...process.env, 
        NODE_OPTIONS: '--experimental-vm-modules' 
      } 
    });
    log('✓ Integration tests completed successfully', colors.green);
    return true;
  } catch (error) {
    log('✗ Integration tests failed', colors.red);
    return false;
  }
}

async function generateCoverageReport() {
  logSection('Generating Coverage Report');
  
  try {
    await runCommand('npx', [
      'jest',
      '--coverage',
      '--coverageDirectory=coverage',
      '--coverageReporters=text',
      '--coverageReporters=lcov',
      '--coverageReporters=html',
      '--detectOpenHandles',
      '--forceExit',
    ]);
    log('✓ Coverage report generated successfully', colors.green);
    log('📊 Coverage report available in ./coverage/lcov-report/index.html', colors.cyan);
    return true;
  } catch (error) {
    log('✗ Coverage report generation failed', colors.red);
    return false;
  }
}

async function runLinting() {
  logSection('Running Code Linting');
  
  try {
    await runCommand('npm', ['run', 'lint']);
    log('✓ Linting completed successfully', colors.green);
    return true;
  } catch (error) {
    log('✗ Linting failed', colors.red);
    return false;
  }
}

async function runSecurityAudit() {
  logSection('Running Security Audit');
  
  try {
    await runCommand('npm', ['audit', '--audit-level=moderate']);
    log('✓ Security audit completed successfully', colors.green);
    return true;
  } catch (error) {
    log('⚠ Security audit found issues', colors.yellow);
    return false;
  }
}

async function runWeek4Tests() {
  logSection('Running Week 4 Specific Tests');
  
  try {
    // Run our custom Week 4 test script
    await runCommand('node', ['scripts/test-week4-simple.js']);
    log('✓ Week 4 functional tests completed successfully', colors.green);
    return true;
  } catch (error) {
    log('✗ Week 4 functional tests failed', colors.red);
    return false;
  }
}

async function main() {
  const startTime = Date.now();
  
  logHeader('UFC Auth API - Comprehensive Test Suite');
  log('Starting comprehensive test execution...', colors.bright);

  const args = process.argv.slice(2);
  const options = {
    unit: args.includes('--unit') || args.includes('--all') || args.length === 0,
    integration: args.includes('--integration') || args.includes('--all') || args.length === 0,
    coverage: args.includes('--coverage') || args.includes('--all'),
    lint: args.includes('--lint') || args.includes('--all'),
    security: args.includes('--security') || args.includes('--all'),
    week4: args.includes('--week4') || args.includes('--all'),
    skipPrereqs: args.includes('--skip-prereqs'),
  };

  const results = {
    prerequisites: true,
    unit: true,
    integration: true,
    coverage: true,
    lint: true,
    security: true,
    week4: true,
  };

  try {
    // Check prerequisites
    if (!options.skipPrereqs) {
      await checkPrerequisites();
    }

    // Run unit tests
    if (options.unit) {
      results.unit = await runUnitTests();
    }

    // Run integration tests
    if (options.integration) {
      results.integration = await runIntegrationTests();
    }

    // Run Week 4 specific tests
    if (options.week4) {
      results.week4 = await runWeek4Tests();
    }

    // Generate coverage report
    if (options.coverage) {
      results.coverage = await generateCoverageReport();
    }

    // Run linting
    if (options.lint) {
      results.lint = await runLinting();
    }

    // Run security audit
    if (options.security) {
      results.security = await runSecurityAudit();
    }

  } catch (error) {
    log(`\n❌ Test execution failed: ${error.message}`, colors.red);
    process.exit(1);
  }

  // Summary
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);

  logHeader('Test Execution Summary');
  
  const testResults = [
    { name: 'Unit Tests', passed: results.unit, enabled: options.unit },
    { name: 'Integration Tests', passed: results.integration, enabled: options.integration },
    { name: 'Week 4 Tests', passed: results.week4, enabled: options.week4 },
    { name: 'Coverage Report', passed: results.coverage, enabled: options.coverage },
    { name: 'Code Linting', passed: results.lint, enabled: options.lint },
    { name: 'Security Audit', passed: results.security, enabled: options.security },
  ];

  testResults.forEach(({ name, passed, enabled }) => {
    if (enabled) {
      const status = passed ? '✓' : '✗';
      const color = passed ? colors.green : colors.red;
      log(`${status} ${name}`, color);
    }
  });

  const allPassed = testResults.every(({ passed, enabled }) => !enabled || passed);
  const totalTests = testResults.filter(({ enabled }) => enabled).length;
  const passedTests = testResults.filter(({ passed, enabled }) => enabled && passed).length;

  log(`\n📊 Results: ${passedTests}/${totalTests} test suites passed`, 
      allPassed ? colors.green : colors.red);
  log(`⏱️  Total execution time: ${duration}s`, colors.cyan);

  if (allPassed) {
    log('\n🎉 All tests passed successfully!', colors.green + colors.bright);
    process.exit(0);
  } else {
    log('\n❌ Some tests failed. Please review the output above.', colors.red + colors.bright);
    process.exit(1);
  }
}

// Handle command line help
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log('UFC Auth API Test Runner', colors.bright);
  log('\nUsage: node scripts/run-tests.js [options]');
  log('\nOptions:');
  log('  --unit          Run unit tests only');
  log('  --integration   Run integration tests only');
  log('  --coverage      Generate coverage report');
  log('  --lint          Run code linting');
  log('  --security      Run security audit');
  log('  --week4         Run Week 4 specific tests');
  log('  --all           Run all tests (default)');
  log('  --skip-prereqs  Skip prerequisite checks');
  log('  --help, -h      Show this help message');
  log('\nExamples:');
  log('  node scripts/run-tests.js                    # Run all tests');
  log('  node scripts/run-tests.js --unit --coverage  # Run unit tests with coverage');
  log('  node scripts/run-tests.js --integration      # Run integration tests only');
  process.exit(0);
}

// Run the main function
main().catch((error) => {
  log(`\n💥 Unexpected error: ${error.message}`, colors.red);
  console.error(error);
  process.exit(1);
}); 
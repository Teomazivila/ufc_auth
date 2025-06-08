#!/usr/bin/env node

import { config } from '../src/config/index.js';
import { connectDatabase, query } from '../src/config/database.js';
import { logger } from '../src/utils/logger.js';
import { Permission } from '../src/models/Permission.js';
import { Role } from '../src/models/Role.js';
import { User } from '../src/models/User.js';

/**
 * RBAC Initialization Script
 * Sets up default roles and permissions for the UFC Auth API
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

// Default permissions to create
const DEFAULT_PERMISSIONS = [
  // User permissions
  { name: 'users:read', description: 'View user information', resource: 'users', action: 'read' },
  { name: 'users:write', description: 'Create and update users', resource: 'users', action: 'write' },
  { name: 'users:delete', description: 'Delete users', resource: 'users', action: 'delete' },
  { name: 'users:manage', description: 'Full user management', resource: 'users', action: 'manage' },
  
  // Role permissions
  { name: 'roles:read', description: 'View roles', resource: 'roles', action: 'read' },
  { name: 'roles:write', description: 'Create and update roles', resource: 'roles', action: 'write' },
  { name: 'roles:delete', description: 'Delete roles', resource: 'roles', action: 'delete' },
  { name: 'roles:manage', description: 'Full role management', resource: 'roles', action: 'manage' },
  
  // Permission permissions
  { name: 'permissions:read', description: 'View permissions', resource: 'permissions', action: 'read' },
  { name: 'permissions:write', description: 'Create and update permissions', resource: 'permissions', action: 'write' },
  { name: 'permissions:delete', description: 'Delete permissions', resource: 'permissions', action: 'delete' },
  { name: 'permissions:manage', description: 'Full permission management', resource: 'permissions', action: 'manage' },
  
  // Profile permissions
  { name: 'profile:read', description: 'View own profile', resource: 'profile', action: 'read' },
  { name: 'profile:write', description: 'Update own profile', resource: 'profile', action: 'write' },
  
  // Authentication permissions
  { name: 'auth:login', description: 'Login to system', resource: 'auth', action: 'login' },
  { name: 'auth:logout', description: 'Logout from system', resource: 'auth', action: 'logout' },
  { name: 'auth:refresh', description: 'Refresh authentication tokens', resource: 'auth', action: 'refresh' },
  { name: 'auth:2fa', description: 'Manage two-factor authentication', resource: 'auth', action: '2fa' },
  
  // System permissions
  { name: 'system:health', description: 'View system health', resource: 'system', action: 'health' },
  { name: 'system:stats', description: 'View system statistics', resource: 'system', action: 'stats' },
  { name: 'system:logs', description: 'View system logs', resource: 'system', action: 'logs' },
  { name: 'system:admin', description: 'Full system administration', resource: 'system', action: 'admin' },
  
  // Audit permissions
  { name: 'audit:read', description: 'View audit logs', resource: 'audit', action: 'read' },
  { name: 'audit:export', description: 'Export audit logs', resource: 'audit', action: 'export' }
];

// Default roles to create
const DEFAULT_ROLES = [
  {
    name: 'admin',
    description: 'System administrator with full access',
    is_system_role: true,
    permissions: [
      'users:manage', 'roles:manage', 'permissions:manage',
      'profile:read', 'profile:write',
      'auth:login', 'auth:logout', 'auth:refresh', 'auth:2fa',
      'system:health', 'system:stats', 'system:logs', 'system:admin',
      'audit:read', 'audit:export'
    ]
  },
  {
    name: 'moderator',
    description: 'Moderator with user management capabilities',
    is_system_role: true,
    permissions: [
      'users:read', 'users:write',
      'roles:read', 'permissions:read',
      'profile:read', 'profile:write',
      'auth:login', 'auth:logout', 'auth:refresh', 'auth:2fa',
      'system:health', 'system:stats',
      'audit:read'
    ]
  },
  {
    name: 'user',
    description: 'Standard user with basic permissions',
    is_system_role: true,
    permissions: [
      'profile:read', 'profile:write',
      'auth:login', 'auth:logout', 'auth:refresh', 'auth:2fa',
      'system:health'
    ]
  },
  {
    name: 'viewer',
    description: 'Read-only access to basic information',
    is_system_role: true,
    permissions: [
      'profile:read',
      'auth:login', 'auth:logout', 'auth:refresh',
      'system:health'
    ]
  }
];

class RBACInitializer {
  constructor() {
    this.createdPermissions = new Map();
    this.createdRoles = new Map();
  }

  async initialize() {
    try {
      logger.info('Starting RBAC initialization...');
      
      // Connect to database
      await connectDatabase();
      
      // Create permissions
      await this.createPermissions();
      
      // Create roles
      await this.createRoles();
      
      // Assign permissions to roles
      await this.assignPermissionsToRoles();
      
      // Create default admin user if specified
      if (process.env.CREATE_ADMIN_USER === 'true') {
        await this.createDefaultAdminUser();
      }
      
      logger.info('RBAC initialization completed successfully!');
      
      // Display summary
      await this.displaySummary();
      
    } catch (error) {
      logger.error('RBAC initialization failed:', error);
      throw error;
    }
  }

  async createPermissions() {
    logger.info('Creating default permissions...');
    
    for (const permissionData of DEFAULT_PERMISSIONS) {
      try {
        // Check if permission already exists
        const existing = await Permission.findByName(permissionData.name);
        if (existing) {
          logger.info(`Permission '${permissionData.name}' already exists, skipping...`);
          this.createdPermissions.set(permissionData.name, existing);
          continue;
        }
        
        // Create permission
        const permission = await Permission.create(permissionData);
        this.createdPermissions.set(permissionData.name, permission);
        logger.info(`Created permission: ${permissionData.name}`);
        
      } catch (error) {
        logger.error(`Failed to create permission '${permissionData.name}':`, error);
        throw error;
      }
    }
    
    logger.info(`Created ${this.createdPermissions.size} permissions`);
  }

  async createRoles() {
    logger.info('Creating default roles...');
    
    for (const roleData of DEFAULT_ROLES) {
      try {
        // Check if role already exists
        const existing = await Role.findByName(roleData.name);
        if (existing) {
          logger.info(`Role '${roleData.name}' already exists, skipping...`);
          this.createdRoles.set(roleData.name, existing);
          continue;
        }
        
        // Create role (without permissions for now)
        const role = await Role.create({
          name: roleData.name,
          description: roleData.description,
          is_system_role: roleData.is_system_role
        });
        
        this.createdRoles.set(roleData.name, role);
        logger.info(`Created role: ${roleData.name}`);
        
      } catch (error) {
        logger.error(`Failed to create role '${roleData.name}':`, error);
        throw error;
      }
    }
    
    logger.info(`Created ${this.createdRoles.size} roles`);
  }

  async assignPermissionsToRoles() {
    logger.info('Assigning permissions to roles...');
    
    for (const roleData of DEFAULT_ROLES) {
      try {
        const role = this.createdRoles.get(roleData.name);
        if (!role) {
          logger.warn(`Role '${roleData.name}' not found, skipping permission assignment`);
          continue;
        }
        
        // Get permission IDs
        const permissionIds = [];
        for (const permissionName of roleData.permissions) {
          const permission = this.createdPermissions.get(permissionName);
          if (permission) {
            permissionIds.push(permission.id);
          } else {
            logger.warn(`Permission '${permissionName}' not found for role '${roleData.name}'`);
          }
        }
        
        // Assign permissions to role
        if (permissionIds.length > 0) {
          await role.setPermissions(permissionIds);
          logger.info(`Assigned ${permissionIds.length} permissions to role '${roleData.name}'`);
        }
        
      } catch (error) {
        logger.error(`Failed to assign permissions to role '${roleData.name}':`, error);
        throw error;
      }
    }
  }

  async createDefaultAdminUser() {
    logger.info('Creating default admin user...');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@ufcauth.local';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!@#';
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    
    try {
      // Check if admin user already exists
      const existingUser = await User.findByEmail(adminEmail);
      if (existingUser) {
        logger.info('Admin user already exists, skipping creation...');
        return;
      }
      
      // Create admin user
      const adminUser = await User.create({
        email: adminEmail,
        username: adminUsername,
        password: adminPassword,
        first_name: 'System',
        last_name: 'Administrator'
      });
      
      // Assign admin role
      const adminRole = this.createdRoles.get('admin');
      if (adminRole) {
        await adminUser.assignRole(adminRole.id);
        logger.info(`Assigned admin role to user '${adminEmail}'`);
      }
      
      // Activate user
      await query(
        'UPDATE users SET status = $1, email_verified = $2 WHERE id = $3',
        ['active', true, adminUser.id]
      );
      
      logger.info(`Created default admin user: ${adminEmail}`);
      logger.warn(`Default admin password: ${adminPassword}`);
      logger.warn('Please change the default admin password after first login!');
      
    } catch (error) {
      logger.error('Failed to create default admin user:', error);
      throw error;
    }
  }

  async displaySummary() {
    logger.info('\n=== RBAC INITIALIZATION SUMMARY ===');
    
    // Count permissions
    const permissionCount = await query('SELECT COUNT(*) as count FROM permissions');
    logger.info(`Total Permissions: ${permissionCount.rows[0].count}`);
    
    // Count roles
    const roleCount = await query('SELECT COUNT(*) as count FROM roles');
    logger.info(`Total Roles: ${roleCount.rows[0].count}`);
    
    // Count users
    const userCount = await query('SELECT COUNT(*) as count FROM users');
    logger.info(`Total Users: ${userCount.rows[0].count}`);
    
    // List roles with permission counts
    const rolesWithPermissions = await query(`
      SELECT r.name, r.description, COUNT(rp.permission_id) as permission_count
      FROM roles r
      LEFT JOIN role_permissions rp ON r.id = rp.role_id
      GROUP BY r.id, r.name, r.description
      ORDER BY r.name
    `);
    
    logger.info('\nRoles and Permission Counts:');
    for (const role of rolesWithPermissions.rows) {
      logger.info(`  ${role.name}: ${role.permission_count} permissions - ${role.description}`);
    }
    
    logger.info('\n=== RBAC SYSTEM READY ===\n');
  }
}

// Run initialization if script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const initializer = new RBACInitializer();
  
  initializer.initialize()
    .then(() => {
      logger.info('RBAC initialization script completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('RBAC initialization script failed:', error);
      process.exit(1);
    });
}

export default RBACInitializer; 
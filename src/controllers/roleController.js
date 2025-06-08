import { Role } from '../models/Role.js';
import { Permission } from '../models/Permission.js';
import { logger } from '../utils/logger.js';
import { validationResult } from 'express-validator';

/**
 * Role Controller for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Create a new role
 */
export const createRole = async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, description, permissions = [] } = req.body;

    // Check if role already exists
    const existingRole = await Role.findByName(name);
    if (existingRole) {
      return res.status(409).json({
        success: false,
        message: 'Role already exists'
      });
    }

    // Create role
    const role = await Role.create({
      name,
      description,
      is_system_role: false
    });

    // Assign permissions if provided
    if (permissions.length > 0) {
      await role.setPermissions(permissions);
    }

    // Fetch role with permissions
    const roleWithPermissions = await Role.findById(role.id);

    logger.info('Role created successfully', {
      roleId: role.id,
      name: role.name,
      createdBy: req.user.id
    });

    res.status(201).json({
      success: true,
      message: 'Role created successfully',
      data: {
        role: roleWithPermissions.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error creating role:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get all roles with pagination
 */
export const getRoles = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      includePermissions = 'false'
    } = req.query;

    const options = {
      page: parseInt(page),
      limit: Math.min(parseInt(limit), 100), // Max 100 per page
      search,
      includePermissions: includePermissions === 'true'
    };

    const result = await Role.findAll(options);

    res.json({
      success: true,
      message: 'Roles retrieved successfully',
      data: {
        roles: result.roles.map(role => role.toSafeObject()),
        pagination: result.pagination
      }
    });
  } catch (error) {
    logger.error('Error getting roles:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get role by ID
 */
export const getRoleById = async (req, res) => {
  try {
    const { roleId } = req.params;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    res.json({
      success: true,
      message: 'Role retrieved successfully',
      data: {
        role: role.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error getting role by ID:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Update role
 */
export const updateRole = async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { roleId } = req.params;
    const { name, description } = req.body;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    // Check if it's a system role
    if (role.is_system_role) {
      return res.status(403).json({
        success: false,
        message: 'Cannot modify system role'
      });
    }

    // Check if new name conflicts with existing role
    if (name && name !== role.name) {
      const existingRole = await Role.findByName(name);
      if (existingRole) {
        return res.status(409).json({
          success: false,
          message: 'Role name already exists'
        });
      }
    }

    // Update role
    await role.update({ name, description });

    logger.info('Role updated successfully', {
      roleId: role.id,
      name: role.name,
      updatedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Role updated successfully',
      data: {
        role: role.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error updating role:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Delete role
 */
export const deleteRole = async (req, res) => {
  try {
    const { roleId } = req.params;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    // Check if it's a system role
    if (role.is_system_role) {
      return res.status(403).json({
        success: false,
        message: 'Cannot delete system role'
      });
    }

    await role.delete();

    logger.info('Role deleted successfully', {
      roleId: role.id,
      name: role.name,
      deletedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Role deleted successfully'
    });
  } catch (error) {
    if (error.message.includes('users are assigned')) {
      return res.status(409).json({
        success: false,
        message: error.message
      });
    }

    logger.error('Error deleting role:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Assign permission to role
 */
export const assignPermissionToRole = async (req, res) => {
  try {
    const { roleId } = req.params;
    const { permissionId } = req.body;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        message: 'Permission not found'
      });
    }

    const assigned = await role.addPermission(permissionId);
    
    if (!assigned) {
      return res.status(409).json({
        success: false,
        message: 'Permission already assigned to role'
      });
    }

    logger.info('Permission assigned to role', {
      roleId: role.id,
      permissionId: permission.id,
      assignedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Permission assigned to role successfully'
    });
  } catch (error) {
    logger.error('Error assigning permission to role:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Remove permission from role
 */
export const removePermissionFromRole = async (req, res) => {
  try {
    const { roleId, permissionId } = req.params;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    const removed = await role.removePermission(permissionId);
    
    if (!removed) {
      return res.status(404).json({
        success: false,
        message: 'Permission not assigned to role'
      });
    }

    logger.info('Permission removed from role', {
      roleId: role.id,
      permissionId,
      removedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Permission removed from role successfully'
    });
  } catch (error) {
    logger.error('Error removing permission from role:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Set role permissions (replace all)
 */
export const setRolePermissions = async (req, res) => {
  try {
    const { roleId } = req.params;
    const { permissions = [] } = req.body;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    // Validate all permissions exist
    if (permissions.length > 0) {
      for (const permissionId of permissions) {
        const permission = await Permission.findById(permissionId);
        if (!permission) {
          return res.status(404).json({
            success: false,
            message: `Permission with ID ${permissionId} not found`
          });
        }
      }
    }

    await role.setPermissions(permissions);

    logger.info('Role permissions set', {
      roleId: role.id,
      permissionCount: permissions.length,
      setBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Role permissions updated successfully'
    });
  } catch (error) {
    logger.error('Error setting role permissions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get role permissions
 */
export const getRolePermissions = async (req, res) => {
  try {
    const { roleId } = req.params;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    res.json({
      success: true,
      message: 'Role permissions retrieved successfully',
      data: {
        role_id: role.id,
        role_name: role.name,
        permissions: role.permissions || []
      }
    });
  } catch (error) {
    logger.error('Error getting role permissions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get users assigned to role
 */
export const getRoleUsers = async (req, res) => {
  try {
    const { roleId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }

    const options = {
      page: parseInt(page),
      limit: Math.min(parseInt(limit), 100)
    };

    const result = await role.getUsers(options);

    res.json({
      success: true,
      message: 'Role users retrieved successfully',
      data: {
        role_id: role.id,
        role_name: role.name,
        users: result.users,
        pagination: result.pagination
      }
    });
  } catch (error) {
    logger.error('Error getting role users:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

export default {
  createRole,
  getRoles,
  getRoleById,
  updateRole,
  deleteRole,
  assignPermissionToRole,
  removePermissionFromRole,
  setRolePermissions,
  getRolePermissions,
  getRoleUsers
}; 
import { Permission } from '../models/Permission.js';
import { logger } from '../utils/logger.js';
import { validationResult } from 'express-validator';

/**
 * Permission Controller for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Create a new permission
 */
export const createPermission = async (req, res) => {
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

    const { name, description, resource, action } = req.body;

    // Check if permission already exists
    const existingPermission = await Permission.findByName(name);
    if (existingPermission) {
      return res.status(409).json({
        success: false,
        message: 'Permission already exists'
      });
    }

    // Check if resource-action combination already exists
    const existingResourceAction = await Permission.findByResourceAction(resource, action);
    if (existingResourceAction) {
      return res.status(409).json({
        success: false,
        message: 'Permission for this resource-action combination already exists'
      });
    }

    // Create permission
    const permission = await Permission.create({
      name,
      description,
      resource,
      action
    });

    logger.info('Permission created successfully', {
      permissionId: permission.id,
      name: permission.name,
      createdBy: req.user.id
    });

    res.status(201).json({
      success: true,
      message: 'Permission created successfully',
      data: {
        permission: permission.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error creating permission:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get all permissions with pagination and filtering
 */
export const getPermissions = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      resource = '',
      action = ''
    } = req.query;

    const options = {
      page: parseInt(page),
      limit: Math.min(parseInt(limit), 100), // Max 100 per page
      search,
      resource,
      action
    };

    const result = await Permission.findAll(options);

    res.json({
      success: true,
      message: 'Permissions retrieved successfully',
      data: {
        permissions: result.permissions.map(permission => permission.toSafeObject()),
        pagination: result.pagination
      }
    });
  } catch (error) {
    logger.error('Error getting permissions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get permission by ID
 */
export const getPermissionById = async (req, res) => {
  try {
    const { permissionId } = req.params;

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        message: 'Permission not found'
      });
    }

    res.json({
      success: true,
      message: 'Permission retrieved successfully',
      data: {
        permission: permission.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error getting permission by ID:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Update permission
 */
export const updatePermission = async (req, res) => {
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

    const { permissionId } = req.params;
    const { name, description, resource, action } = req.body;

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        message: 'Permission not found'
      });
    }

    // Check if new name conflicts with existing permission
    if (name && name !== permission.name) {
      const existingPermission = await Permission.findByName(name);
      if (existingPermission) {
        return res.status(409).json({
          success: false,
          message: 'Permission name already exists'
        });
      }
    }

    // Check if new resource-action combination conflicts
    if ((resource && resource !== permission.resource) || (action && action !== permission.action)) {
      const newResource = resource || permission.resource;
      const newAction = action || permission.action;
      
      const existingResourceAction = await Permission.findByResourceAction(newResource, newAction);
      if (existingResourceAction && existingResourceAction.id !== permission.id) {
        return res.status(409).json({
          success: false,
          message: 'Permission for this resource-action combination already exists'
        });
      }
    }

    // Update permission
    await permission.update({ name, description, resource, action });

    logger.info('Permission updated successfully', {
      permissionId: permission.id,
      name: permission.name,
      updatedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Permission updated successfully',
      data: {
        permission: permission.toSafeObject()
      }
    });
  } catch (error) {
    logger.error('Error updating permission:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Delete permission
 */
export const deletePermission = async (req, res) => {
  try {
    const { permissionId } = req.params;

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        message: 'Permission not found'
      });
    }

    await permission.delete();

    logger.info('Permission deleted successfully', {
      permissionId: permission.id,
      name: permission.name,
      deletedBy: req.user.id
    });

    res.json({
      success: true,
      message: 'Permission deleted successfully'
    });
  } catch (error) {
    if (error.message.includes('assigned to')) {
      return res.status(409).json({
        success: false,
        message: error.message
      });
    }

    logger.error('Error deleting permission:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get all unique resources
 */
export const getResources = async (req, res) => {
  try {
    const resources = await Permission.getResources();

    res.json({
      success: true,
      message: 'Resources retrieved successfully',
      data: {
        resources
      }
    });
  } catch (error) {
    logger.error('Error getting resources:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get all unique actions
 */
export const getActions = async (req, res) => {
  try {
    const actions = await Permission.getActions();

    res.json({
      success: true,
      message: 'Actions retrieved successfully',
      data: {
        actions
      }
    });
  } catch (error) {
    logger.error('Error getting actions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get permissions by resource
 */
export const getPermissionsByResource = async (req, res) => {
  try {
    const { resource } = req.params;

    const permissions = await Permission.findByResource(resource);

    res.json({
      success: true,
      message: 'Permissions retrieved successfully',
      data: {
        resource,
        permissions: permissions.map(permission => permission.toSafeObject())
      }
    });
  } catch (error) {
    logger.error('Error getting permissions by resource:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Get roles that have this permission
 */
export const getPermissionRoles = async (req, res) => {
  try {
    const { permissionId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        message: 'Permission not found'
      });
    }

    const options = {
      page: parseInt(page),
      limit: Math.min(parseInt(limit), 100)
    };

    const result = await permission.getRoles(options);

    res.json({
      success: true,
      message: 'Permission roles retrieved successfully',
      data: {
        permission_id: permission.id,
        permission_name: permission.name,
        roles: result.roles,
        pagination: result.pagination
      }
    });
  } catch (error) {
    logger.error('Error getting permission roles:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * Create multiple permissions at once (bulk create)
 */
export const createBulkPermissions = async (req, res) => {
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

    const { permissions } = req.body;

    if (!Array.isArray(permissions) || permissions.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Permissions array is required and cannot be empty'
      });
    }

    // Validate each permission
    for (const perm of permissions) {
      if (!perm.name || !perm.resource || !perm.action) {
        return res.status(400).json({
          success: false,
          message: 'Each permission must have name, resource, and action'
        });
      }
    }

    const createdPermissions = await Permission.createBulk(permissions);

    logger.info('Bulk permissions created successfully', {
      count: createdPermissions.length,
      createdBy: req.user.id
    });

    res.status(201).json({
      success: true,
      message: `${createdPermissions.length} permissions created successfully`,
      data: {
        permissions: createdPermissions.map(permission => permission.toSafeObject())
      }
    });
  } catch (error) {
    logger.error('Error creating bulk permissions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

export default {
  createPermission,
  getPermissions,
  getPermissionById,
  updatePermission,
  deletePermission,
  getResources,
  getActions,
  getPermissionsByResource,
  getPermissionRoles,
  createBulkPermissions
}; 
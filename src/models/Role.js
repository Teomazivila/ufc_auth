import { query } from '../config/database.js';
import { logger } from '../utils/logger.js';

/**
 * Role Model for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */
export class Role {
  constructor(roleData) {
    this.id = roleData.id;
    this.name = roleData.name;
    this.description = roleData.description;
    this.is_system_role = roleData.is_system_role;
    this.created_at = roleData.created_at;
    this.updated_at = roleData.updated_at;
    this.permissions = roleData.permissions || [];
  }

  /**
   * Create a new role
   */
  static async create(roleData) {
    const { name, description, is_system_role = false } = roleData;
    
    try {
      const queryText = `
        INSERT INTO roles (name, description, is_system_role)
        VALUES ($1, $2, $3)
        RETURNING *
      `;
      
      const values = [name, description, is_system_role];
      const result = await query(queryText, values);
      
      logger.info('Role created successfully', { 
        roleId: result.rows[0].id, 
        name: result.rows[0].name 
      });
      
      return new Role(result.rows[0]);
    } catch (error) {
      logger.error('Error creating role:', error);
      throw error;
    }
  }

  /**
   * Find role by ID with permissions
   */
  static async findById(id) {
    try {
      const queryText = `
        SELECT r.*, 
               COALESCE(
                 json_agg(
                   json_build_object(
                     'id', p.id,
                     'name', p.name,
                     'description', p.description,
                     'resource', p.resource,
                     'action', p.action
                   )
                 ) FILTER (WHERE p.id IS NOT NULL), 
                 '[]'
               ) as permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id
        WHERE r.id = $1
        GROUP BY r.id
      `;
      
      const result = await query(queryText, [id]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new Role(result.rows[0]);
    } catch (error) {
      logger.error('Error finding role by ID:', error);
      throw error;
    }
  }

  /**
   * Find role by name with permissions
   */
  static async findByName(name) {
    try {
      const queryText = `
        SELECT r.*, 
               COALESCE(
                 json_agg(
                   json_build_object(
                     'id', p.id,
                     'name', p.name,
                     'description', p.description,
                     'resource', p.resource,
                     'action', p.action
                   )
                 ) FILTER (WHERE p.id IS NOT NULL), 
                 '[]'
               ) as permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id
        WHERE r.name = $1
        GROUP BY r.id
      `;
      
      const result = await query(queryText, [name]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new Role(result.rows[0]);
    } catch (error) {
      logger.error('Error finding role by name:', error);
      throw error;
    }
  }

  /**
   * Get all roles with pagination
   */
  static async findAll(options = {}) {
    const { page = 1, limit = 10, search = '', includePermissions = false } = options;
    const offset = (page - 1) * limit;

    try {
      let queryText;
      let countQuery;
      let queryParams;

      if (includePermissions) {
        queryText = `
          SELECT r.*, 
                 COALESCE(
                   json_agg(
                     json_build_object(
                       'id', p.id,
                       'name', p.name,
                       'description', p.description,
                       'resource', p.resource,
                       'action', p.action
                     )
                   ) FILTER (WHERE p.id IS NOT NULL), 
                   '[]'
                 ) as permissions
          FROM roles r
          LEFT JOIN role_permissions rp ON r.id = rp.role_id
          LEFT JOIN permissions p ON rp.permission_id = p.id
          WHERE ($3 = '' OR r.name ILIKE $3 OR r.description ILIKE $3)
          GROUP BY r.id
          ORDER BY r.created_at DESC
          LIMIT $1 OFFSET $2
        `;
        queryParams = [limit, offset, search ? `%${search}%` : ''];
      } else {
        queryText = `
          SELECT * FROM roles
          WHERE ($3 = '' OR name ILIKE $3 OR description ILIKE $3)
          ORDER BY created_at DESC
          LIMIT $1 OFFSET $2
        `;
        queryParams = [limit, offset, search ? `%${search}%` : ''];
      }

      countQuery = `
        SELECT COUNT(*) as total
        FROM roles
        WHERE ($1 = '' OR name ILIKE $1 OR description ILIKE $1)
      `;

      const [rolesResult, countResult] = await Promise.all([
        query(queryText, queryParams),
        query(countQuery, [search ? `%${search}%` : ''])
      ]);

      const roles = rolesResult.rows.map(row => new Role(row));
      const total = parseInt(countResult.rows[0].total);

      return {
        roles,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error finding all roles:', error);
      throw error;
    }
  }

  /**
   * Update role
   */
  async update(updateData) {
    const { name, description } = updateData;
    
    try {
      const queryText = `
        UPDATE roles 
        SET name = COALESCE($1, name),
            description = COALESCE($2, description),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
        RETURNING *
      `;
      
      const values = [name, description, this.id];
      const result = await query(queryText, values);
      
      if (result.rows.length === 0) {
        throw new Error('Role not found');
      }

      // Update instance properties
      Object.assign(this, result.rows[0]);
      
      logger.info('Role updated successfully', { 
        roleId: this.id, 
        name: this.name 
      });
      
      return this;
    } catch (error) {
      logger.error('Error updating role:', error);
      throw error;
    }
  }

  /**
   * Delete role (only if not system role and no users assigned)
   */
  async delete() {
    try {
      if (this.is_system_role) {
        throw new Error('Cannot delete system role');
      }

      // Check if role has users assigned
      const userCheckQuery = `
        SELECT COUNT(*) as user_count
        FROM user_roles
        WHERE role_id = $1
      `;
      
      const userCheck = await query(userCheckQuery, [this.id]);
      const userCount = parseInt(userCheck.rows[0].user_count);

      if (userCount > 0) {
        throw new Error(`Cannot delete role: ${userCount} users are assigned to this role`);
      }

      // Delete role permissions first
      await query('DELETE FROM role_permissions WHERE role_id = $1', [this.id]);
      
      // Delete role
      const deleteQuery = 'DELETE FROM roles WHERE id = $1 RETURNING *';
      const result = await query(deleteQuery, [this.id]);
      
      if (result.rows.length === 0) {
        throw new Error('Role not found');
      }

      logger.info('Role deleted successfully', { 
        roleId: this.id, 
        name: this.name 
      });
      
      return true;
    } catch (error) {
      logger.error('Error deleting role:', error);
      throw error;
    }
  }

  /**
   * Add permission to role
   */
  async addPermission(permissionId) {
    try {
      const queryText = `
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES ($1, $2)
        ON CONFLICT (role_id, permission_id) DO NOTHING
        RETURNING *
      `;
      
      const result = await query(queryText, [this.id, permissionId]);
      
      logger.info('Permission added to role', { 
        roleId: this.id, 
        permissionId,
        roleName: this.name 
      });
      
      return result.rows.length > 0;
    } catch (error) {
      logger.error('Error adding permission to role:', error);
      throw error;
    }
  }

  /**
   * Remove permission from role
   */
  async removePermission(permissionId) {
    try {
      const queryText = `
        DELETE FROM role_permissions
        WHERE role_id = $1 AND permission_id = $2
        RETURNING *
      `;
      
      const result = await query(queryText, [this.id, permissionId]);
      
      logger.info('Permission removed from role', { 
        roleId: this.id, 
        permissionId,
        roleName: this.name 
      });
      
      return result.rows.length > 0;
    } catch (error) {
      logger.error('Error removing permission from role:', error);
      throw error;
    }
  }

  /**
   * Set permissions for role (replace all)
   */
  async setPermissions(permissionIds) {
    try {
      // Start transaction
      await query('BEGIN');

      // Remove all existing permissions
      await query('DELETE FROM role_permissions WHERE role_id = $1', [this.id]);

      // Add new permissions
      if (permissionIds && permissionIds.length > 0) {
        const values = permissionIds.map((permId, index) => 
          `($1, $${index + 2})`
        ).join(', ');
        
        const insertQuery = `
          INSERT INTO role_permissions (role_id, permission_id)
          VALUES ${values}
        `;
        
        await query(insertQuery, [this.id, ...permissionIds]);
      }

      await query('COMMIT');

      logger.info('Permissions set for role', { 
        roleId: this.id, 
        permissionCount: permissionIds?.length || 0,
        roleName: this.name 
      });
      
      return true;
    } catch (error) {
      await query('ROLLBACK');
      logger.error('Error setting permissions for role:', error);
      throw error;
    }
  }

  /**
   * Check if role has specific permission
   */
  hasPermission(permissionName) {
    if (!this.permissions || !Array.isArray(this.permissions)) {
      return false;
    }
    
    return this.permissions.some(permission => permission.name === permissionName);
  }

  /**
   * Get users assigned to this role
   */
  async getUsers(options = {}) {
    const { page = 1, limit = 10 } = options;
    const offset = (page - 1) * limit;

    try {
      const queryText = `
        SELECT u.id, u.email, u.username, u.first_name, u.last_name, 
               u.status, u.created_at, ur.assigned_at
        FROM users u
        INNER JOIN user_roles ur ON u.id = ur.user_id
        WHERE ur.role_id = $1
        ORDER BY ur.assigned_at DESC
        LIMIT $2 OFFSET $3
      `;

      const countQuery = `
        SELECT COUNT(*) as total
        FROM user_roles
        WHERE role_id = $1
      `;

      const [usersResult, countResult] = await Promise.all([
        query(queryText, [this.id, limit, offset]),
        query(countQuery, [this.id])
      ]);

      const total = parseInt(countResult.rows[0].total);

      return {
        users: usersResult.rows,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting users for role:', error);
      throw error;
    }
  }

  /**
   * Get safe role data (for API responses)
   */
  toSafeObject() {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      is_system_role: this.is_system_role,
      permissions: this.permissions,
      created_at: this.created_at,
      updated_at: this.updated_at
    };
  }
}

export default Role; 
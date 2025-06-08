import { query } from '../config/database.js';
import { logger } from '../utils/logger.js';

/**
 * Permission Model for RBAC system
 * Following 2025 best practices for Node.js 20+ and Express.js
 */
export class Permission {
  constructor(permissionData) {
    this.id = permissionData.id;
    this.name = permissionData.name;
    this.description = permissionData.description;
    this.resource = permissionData.resource;
    this.action = permissionData.action;
    this.created_at = permissionData.created_at;
    this.updated_at = permissionData.updated_at;
  }

  /**
   * Create a new permission
   */
  static async create(permissionData) {
    const { name, description, resource, action } = permissionData;
    
    try {
      const queryText = `
        INSERT INTO permissions (name, description, resource, action)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `;
      
      const values = [name, description, resource, action];
      const result = await query(queryText, values);
      
      logger.info('Permission created successfully', { 
        permissionId: result.rows[0].id, 
        name: result.rows[0].name 
      });
      
      return new Permission(result.rows[0]);
    } catch (error) {
      logger.error('Error creating permission:', error);
      throw error;
    }
  }

  /**
   * Find permission by ID
   */
  static async findById(id) {
    try {
      const queryText = 'SELECT * FROM permissions WHERE id = $1';
      const result = await query(queryText, [id]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new Permission(result.rows[0]);
    } catch (error) {
      logger.error('Error finding permission by ID:', error);
      throw error;
    }
  }

  /**
   * Find permission by name
   */
  static async findByName(name) {
    try {
      const queryText = 'SELECT * FROM permissions WHERE name = $1';
      const result = await query(queryText, [name]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new Permission(result.rows[0]);
    } catch (error) {
      logger.error('Error finding permission by name:', error);
      throw error;
    }
  }

  /**
   * Find permissions by resource and action
   */
  static async findByResourceAction(resource, action) {
    try {
      const queryText = 'SELECT * FROM permissions WHERE resource = $1 AND action = $2';
      const result = await query(queryText, [resource, action]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new Permission(result.rows[0]);
    } catch (error) {
      logger.error('Error finding permission by resource and action:', error);
      throw error;
    }
  }

  /**
   * Get all permissions with pagination and filtering
   */
  static async findAll(options = {}) {
    const { 
      page = 1, 
      limit = 10, 
      search = '', 
      resource = '', 
      action = '' 
    } = options;
    const offset = (page - 1) * limit;

    try {
      let whereConditions = [];
      let queryParams = [limit, offset];
      let paramIndex = 3;

      // Build dynamic WHERE clause
      if (search) {
        whereConditions.push(`(name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
        queryParams.push(`%${search}%`);
        paramIndex++;
      }

      if (resource) {
        whereConditions.push(`resource = $${paramIndex}`);
        queryParams.push(resource);
        paramIndex++;
      }

      if (action) {
        whereConditions.push(`action = $${paramIndex}`);
        queryParams.push(action);
        paramIndex++;
      }

      const whereClause = whereConditions.length > 0 
        ? `WHERE ${whereConditions.join(' AND ')}`
        : '';

      const queryText = `
        SELECT * FROM permissions
        ${whereClause}
        ORDER BY resource, action, name
        LIMIT $1 OFFSET $2
      `;

      const countQuery = `
        SELECT COUNT(*) as total
        FROM permissions
        ${whereClause}
      `;

      const [permissionsResult, countResult] = await Promise.all([
        query(queryText, queryParams),
        query(countQuery, queryParams.slice(2)) // Remove limit and offset for count
      ]);

      const permissions = permissionsResult.rows.map(row => new Permission(row));
      const total = parseInt(countResult.rows[0].total);

      return {
        permissions,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error finding all permissions:', error);
      throw error;
    }
  }

  /**
   * Get all unique resources
   */
  static async getResources() {
    try {
      const queryText = `
        SELECT DISTINCT resource
        FROM permissions
        ORDER BY resource
      `;
      
      const result = await query(queryText);
      return result.rows.map(row => row.resource);
    } catch (error) {
      logger.error('Error getting resources:', error);
      throw error;
    }
  }

  /**
   * Get all unique actions
   */
  static async getActions() {
    try {
      const queryText = `
        SELECT DISTINCT action
        FROM permissions
        ORDER BY action
      `;
      
      const result = await query(queryText);
      return result.rows.map(row => row.action);
    } catch (error) {
      logger.error('Error getting actions:', error);
      throw error;
    }
  }

  /**
   * Get permissions by resource
   */
  static async findByResource(resource) {
    try {
      const queryText = `
        SELECT * FROM permissions
        WHERE resource = $1
        ORDER BY action, name
      `;
      
      const result = await query(queryText, [resource]);
      return result.rows.map(row => new Permission(row));
    } catch (error) {
      logger.error('Error finding permissions by resource:', error);
      throw error;
    }
  }

  /**
   * Update permission
   */
  async update(updateData) {
    const { name, description, resource, action } = updateData;
    
    try {
      const queryText = `
        UPDATE permissions 
        SET name = COALESCE($1, name),
            description = COALESCE($2, description),
            resource = COALESCE($3, resource),
            action = COALESCE($4, action),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $5
        RETURNING *
      `;
      
      const values = [name, description, resource, action, this.id];
      const result = await query(queryText, values);
      
      if (result.rows.length === 0) {
        throw new Error('Permission not found');
      }

      // Update instance properties
      Object.assign(this, result.rows[0]);
      
      logger.info('Permission updated successfully', { 
        permissionId: this.id, 
        name: this.name 
      });
      
      return this;
    } catch (error) {
      logger.error('Error updating permission:', error);
      throw error;
    }
  }

  /**
   * Delete permission (check if used by roles first)
   */
  async delete() {
    try {
      // Check if permission is assigned to any roles
      const roleCheckQuery = `
        SELECT COUNT(*) as role_count
        FROM role_permissions
        WHERE permission_id = $1
      `;
      
      const roleCheck = await query(roleCheckQuery, [this.id]);
      const roleCount = parseInt(roleCheck.rows[0].role_count);

      if (roleCount > 0) {
        throw new Error(`Cannot delete permission: it is assigned to ${roleCount} role(s)`);
      }

      // Delete permission
      const deleteQuery = 'DELETE FROM permissions WHERE id = $1 RETURNING *';
      const result = await query(deleteQuery, [this.id]);
      
      if (result.rows.length === 0) {
        throw new Error('Permission not found');
      }

      logger.info('Permission deleted successfully', { 
        permissionId: this.id, 
        name: this.name 
      });
      
      return true;
    } catch (error) {
      logger.error('Error deleting permission:', error);
      throw error;
    }
  }

  /**
   * Get roles that have this permission
   */
  async getRoles(options = {}) {
    const { page = 1, limit = 10 } = options;
    const offset = (page - 1) * limit;

    try {
      const queryText = `
        SELECT r.id, r.name, r.description, r.is_system_role, 
               r.created_at, rp.assigned_at
        FROM roles r
        INNER JOIN role_permissions rp ON r.id = rp.role_id
        WHERE rp.permission_id = $1
        ORDER BY r.name
        LIMIT $2 OFFSET $3
      `;

      const countQuery = `
        SELECT COUNT(*) as total
        FROM role_permissions
        WHERE permission_id = $1
      `;

      const [rolesResult, countResult] = await Promise.all([
        query(queryText, [this.id, limit, offset]),
        query(countQuery, [this.id])
      ]);

      const total = parseInt(countResult.rows[0].total);

      return {
        roles: rolesResult.rows,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting roles for permission:', error);
      throw error;
    }
  }

  /**
   * Create multiple permissions at once (bulk create)
   */
  static async createBulk(permissionsData) {
    try {
      if (!Array.isArray(permissionsData) || permissionsData.length === 0) {
        throw new Error('Invalid permissions data');
      }

      await query('BEGIN');

      const permissions = [];
      for (const permData of permissionsData) {
        const { name, description, resource, action } = permData;
        
        const queryText = `
          INSERT INTO permissions (name, description, resource, action)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (name) DO NOTHING
          RETURNING *
        `;
        
        const result = await query(queryText, [name, description, resource, action]);
        
        if (result.rows.length > 0) {
          permissions.push(new Permission(result.rows[0]));
        }
      }

      await query('COMMIT');

      logger.info('Bulk permissions created successfully', { 
        count: permissions.length 
      });

      return permissions;
    } catch (error) {
      await query('ROLLBACK');
      logger.error('Error creating bulk permissions:', error);
      throw error;
    }
  }

  /**
   * Get safe permission data (for API responses)
   */
  toSafeObject() {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      resource: this.resource,
      action: this.action,
      created_at: this.created_at,
      updated_at: this.updated_at
    };
  }
}

export default Permission; 
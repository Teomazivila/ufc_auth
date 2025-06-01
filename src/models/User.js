import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import crypto from 'crypto';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { getPool, query } from '../config/database.js';
import { getRedisClient } from '../config/redis.js';

/**
 * User Model with modern authentication features
 * Following 2025 best practices for Node.js 20+ and Express.js
 */
export class User {
  constructor(userData) {
    this.id = userData.id;
    this.email = userData.email;
    this.username = userData.username;
    this.password_hash = userData.password_hash;
    this.first_name = userData.first_name;
    this.last_name = userData.last_name;
    this.is_active = userData.is_active;
    this.is_verified = userData.is_verified;
    this.two_factor_enabled = userData.two_factor_enabled;
    this.two_factor_secret = userData.two_factor_secret;
    this.backup_codes = userData.backup_codes;
    this.failed_login_attempts = userData.failed_login_attempts;
    this.locked_until = userData.locked_until;
    this.last_login = userData.last_login;
    this.created_at = userData.created_at;
    this.updated_at = userData.updated_at;
  }

  /**
   * Create a new user with secure password hashing
   */
  static async create(userData) {
    const { email, username, password, first_name, last_name } = userData;
    
    try {
      // Hash password with bcrypt (cost factor 12 for 2025 security standards)
      const password_hash = await bcrypt.hash(password, 12);
      
      const queryText = `
        INSERT INTO users (email, username, password_hash, first_name, last_name)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `;
      
      const values = [email, username, password_hash, first_name, last_name];
      const result = await query(queryText, values);
      
      logger.info('User created successfully', { 
        userId: result.rows[0].id, 
        email: result.rows[0].email 
      });
      
      return new User(result.rows[0]);
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Find user by email
   */
  static async findByEmail(email) {
    try {
      const queryText = 'SELECT * FROM users WHERE email = $1';
      const result = await query(queryText, [email]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new User(result.rows[0]);
    } catch (error) {
      logger.error('Error finding user by email:', error);
      throw error;
    }
  }

  /**
   * Find user by ID
   */
  static async findById(id) {
    try {
      const queryText = 'SELECT * FROM users WHERE id = $1';
      const result = await query(queryText, [id]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return new User(result.rows[0]);
    } catch (error) {
      logger.error('Error finding user by ID:', error);
      throw error;
    }
  }

  /**
   * Verify password using bcrypt
   */
  async verifyPassword(password) {
    try {
      return await bcrypt.compare(password, this.password_hash);
    } catch (error) {
      logger.error('Error verifying password:', error);
      return false;
    }
  }

  /**
   * Generate JWT access token
   */
  generateAccessToken() {
    const payload = {
      id: this.id,
      email: this.email,
      username: this.username,
      type: 'access'
    };

    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    });
  }

  /**
   * Generate JWT refresh token
   */
  generateRefreshToken() {
    const payload = {
      id: this.id,
      email: this.email,
      type: 'refresh',
      jti: crypto.randomUUID() // Unique token ID for revocation
    };

    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiresIn,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    });
  }

  /**
   * Store refresh token in Redis with expiration
   */
  async storeRefreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);
      const key = `refresh_token:${this.id}:${decoded.jti}`;
      
      // Store for the same duration as token expiration
      const expirationSeconds = Math.floor((decoded.exp - decoded.iat));
      await getRedisClient().setEx(key, expirationSeconds, refreshToken);
      
      logger.info('Refresh token stored', { userId: this.id, jti: decoded.jti });
    } catch (error) {
      logger.error('Error storing refresh token:', error);
      throw error;
    }
  }

  /**
   * Verify and retrieve refresh token from Redis
   */
  static async verifyRefreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);
      const key = `refresh_token:${decoded.id}:${decoded.jti}`;
      
      const storedToken = await getRedisClient().get(key);
      if (!storedToken || storedToken !== refreshToken) {
        throw new Error('Invalid refresh token');
      }
      
      return decoded;
    } catch (error) {
      logger.error('Error verifying refresh token:', error);
      throw error;
    }
  }

  /**
   * Revoke refresh token
   */
  async revokeRefreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);
      const key = `refresh_token:${this.id}:${decoded.jti}`;
      
      await getRedisClient().del(key);
      logger.info('Refresh token revoked', { userId: this.id, jti: decoded.jti });
    } catch (error) {
      logger.error('Error revoking refresh token:', error);
      throw error;
    }
  }

  /**
   * Revoke all refresh tokens for user
   */
  async revokeAllRefreshTokens() {
    try {
      const pattern = `refresh_token:${this.id}:*`;
      const keys = await getRedisClient().keys(pattern);
      
      if (keys.length > 0) {
        await getRedisClient().del(keys);
        logger.info('All refresh tokens revoked', { userId: this.id, count: keys.length });
      }
    } catch (error) {
      logger.error('Error revoking all refresh tokens:', error);
      throw error;
    }
  }

  /**
   * Setup 2FA - generate secret and return QR code data
   */
  async setup2FA() {
    try {
      const secret = speakeasy.generateSecret({
        name: `${config.twoFactor.serviceName} (${this.email})`,
        issuer: config.twoFactor.issuer,
        length: 32
      });

      // Store secret temporarily (not activated until verified)
      const tempKey = `2fa_setup:${this.id}`;
      await getRedisClient().setEx(tempKey, 300, secret.base32); // 5 minutes expiration

      return {
        secret: secret.base32,
        qrCode: secret.otpauth_url,
        manualEntryKey: secret.base32
      };
    } catch (error) {
      logger.error('Error setting up 2FA:', error);
      throw error;
    }
  }

  /**
   * Verify 2FA token and activate if setup
   */
  async verify2FA(token, isSetup = false) {
    try {
      let secret = this.two_factor_secret;
      
      if (isSetup) {
        // Get temporary secret from Redis
        const tempKey = `2fa_setup:${this.id}`;
        secret = await getRedisClient().get(tempKey);
        
        if (!secret) {
          throw new Error('2FA setup session expired');
        }
      }

      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2 // Allow 2 time steps tolerance
      });

      if (verified && isSetup) {
        // Activate 2FA and generate backup codes
        await this.activate2FA(secret);
        
        // Clean up temporary setup
        const tempKey = `2fa_setup:${this.id}`;
        await getRedisClient().del(tempKey);
      }

      return verified;
    } catch (error) {
      logger.error('Error verifying 2FA:', error);
      throw error;
    }
  }

  /**
   * Activate 2FA with backup codes
   */
  async activate2FA(secret) {
    try {
      // Generate 10 backup codes
      const backupCodes = Array.from({ length: 10 }, () => 
        crypto.randomBytes(4).toString('hex').toUpperCase()
      );

      const query = `
        UPDATE users 
        SET two_factor_enabled = true, 
            two_factor_secret = $1, 
            backup_codes = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
      `;

      await query(query, [secret, JSON.stringify(backupCodes), this.id]);
      
      this.two_factor_enabled = true;
      this.two_factor_secret = secret;
      this.backup_codes = backupCodes;

      logger.info('2FA activated for user', { userId: this.id });
      
      return backupCodes;
    } catch (error) {
      logger.error('Error activating 2FA:', error);
      throw error;
    }
  }

  /**
   * Disable 2FA
   */
  async disable2FA() {
    try {
      const query = `
        UPDATE users 
        SET two_factor_enabled = false, 
            two_factor_secret = NULL, 
            backup_codes = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `;

      await query(query, [this.id]);
      
      this.two_factor_enabled = false;
      this.two_factor_secret = null;
      this.backup_codes = null;

      logger.info('2FA disabled for user', { userId: this.id });
    } catch (error) {
      logger.error('Error disabling 2FA:', error);
      throw error;
    }
  }

  /**
   * Use backup code for 2FA
   */
  async useBackupCode(code) {
    try {
      if (!this.backup_codes || !Array.isArray(this.backup_codes)) {
        return false;
      }

      const codeIndex = this.backup_codes.indexOf(code.toUpperCase());
      if (codeIndex === -1) {
        return false;
      }

      // Remove used backup code
      this.backup_codes.splice(codeIndex, 1);

      const query = `
        UPDATE users 
        SET backup_codes = $1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `;

      await query(query, [JSON.stringify(this.backup_codes), this.id]);

      logger.info('Backup code used', { userId: this.id, remainingCodes: this.backup_codes.length });
      
      return true;
    } catch (error) {
      logger.error('Error using backup code:', error);
      throw error;
    }
  }

  /**
   * Record failed login attempt
   */
  async recordFailedLogin() {
    try {
      const attempts = (this.failed_login_attempts || 0) + 1;
      let lockedUntil = null;

      // Lock account after 5 failed attempts for 15 minutes
      if (attempts >= 5) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }

      const query = `
        UPDATE users 
        SET failed_login_attempts = $1, 
            locked_until = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
      `;

      await query(query, [attempts, lockedUntil, this.id]);
      
      this.failed_login_attempts = attempts;
      this.locked_until = lockedUntil;

      logger.warn('Failed login attempt recorded', { 
        userId: this.id, 
        attempts, 
        locked: !!lockedUntil 
      });
    } catch (error) {
      logger.error('Error recording failed login:', error);
      throw error;
    }
  }

  /**
   * Reset failed login attempts on successful login
   */
  async resetFailedLogins() {
    try {
      const query = `
        UPDATE users 
        SET failed_login_attempts = 0, 
            locked_until = NULL,
            last_login = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `;

      await query(query, [this.id]);
      
      this.failed_login_attempts = 0;
      this.locked_until = null;
      this.last_login = new Date();

      logger.info('Failed login attempts reset', { userId: this.id });
    } catch (error) {
      logger.error('Error resetting failed logins:', error);
      throw error;
    }
  }

  /**
   * Check if account is locked
   */
  isLocked() {
    if (!this.locked_until) return false;
    return new Date() < new Date(this.locked_until);
  }

  /**
   * Get safe user data (without sensitive information)
   */
  toSafeObject() {
    return {
      id: this.id,
      email: this.email,
      username: this.username,
      first_name: this.first_name,
      last_name: this.last_name,
      is_active: this.is_active,
      is_verified: this.is_verified,
      two_factor_enabled: this.two_factor_enabled,
      last_login: this.last_login,
      created_at: this.created_at
    };
  }
}

export default User; 
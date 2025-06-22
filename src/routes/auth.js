import { Router } from 'express';
import qrcode from 'qrcode';
import { asyncHandler } from '../middleware/errorHandler.js';
import { 
  authenticateToken, 
  authRateLimit, 
  blacklistToken,
  verify2FAToken,
  require2FA 
} from '../middleware/auth.js';
import { User } from '../models/User.js';
import { 
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  setup2FASchema,
  verify2FASchema,
  changePasswordSchema,
  resetPasswordRequestSchema,
  resetPasswordConfirmSchema,
  validateBody
} from '../schemas/authSchemas.js';
import { 
  UnauthorizedError, 
  ConflictError, 
  NotFoundError,
  ForbiddenError 
} from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';
import { config } from '../config/index.js';
import { query } from '../config/database.js';

const router = Router();

/**
 * Authentication Routes
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     tags: [Authentication]
 *     summary: Register a new user account
 *     description: |
 *       Create a new user account with email verification. The user will receive an email
 *       to verify their account before they can login.
 *       
 *       ### Security Features:
 *       - Email uniqueness validation
 *       - Strong password requirements
 *       - Rate limiting protection
 *       - Input sanitization
 *       
 *       ### Response:
 *       Returns JWT tokens immediately after registration for seamless UX.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - username
 *               - password
 *               - firstName
 *               - lastName
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "john.doe@example.com"
 *                 description: Valid email address (must be unique)
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 30
 *                 pattern: "^[a-zA-Z0-9_-]+$"
 *                 example: "johndoe"
 *                 description: Unique username (alphanumeric, underscore, dash only)
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 example: "SecurePass123!"
 *                 description: |
 *                   Strong password requirements:
 *                   - Minimum 8 characters
 *                   - At least one uppercase letter
 *                   - At least one lowercase letter  
 *                   - At least one number
 *                   - At least one special character
 *               firstName:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 50
 *                 example: "John"
 *                 description: User's first name
 *               lastName:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 50
 *                 example: "Doe"
 *                 description: User's last name
 *           examples:
 *             newUser:
 *               summary: New user registration
 *               value:
 *                 email: "john.doe@example.com"
 *                 username: "johndoe"
 *                 password: "SecurePass123!"
 *                 firstName: "John"
 *                 lastName: "Doe"
 *     responses:
 *       '201':
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     message:
 *                       type: string
 *                       example: "Registration successful"
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     tokens:
 *                       $ref: '#/components/schemas/JWTTokens'
 *             examples:
 *               success:
 *                 summary: Successful registration
 *                 value:
 *                   success: true
 *                   data:
 *                     message: "Registration successful"
 *                     user:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       email: "john.doe@example.com"
 *                       username: "johndoe"
 *                       firstName: "John"
 *                       lastName: "Doe"
 *                       status: "pending_verification"
 *                       emailVerified: false
 *                       twoFactorEnabled: false
 *                       createdAt: "2025-01-15T10:30:00.000Z"
 *                     tokens:
 *                       accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                       refreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                       expiresIn: "15m"
 *                       tokenType: "Bearer"
 *       '400':
 *         $ref: '#/components/responses/ValidationError'
 *       '409':
 *         description: User already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "User with this email already exists"
 *                 code:
 *                   type: string
 *                   example: "USER_EXISTS"
 *       '429':
 *         $ref: '#/components/responses/RateLimit'
 *       '500':
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/register', 
  authRateLimit,
  validateBody(registerSchema),
  asyncHandler(async (req, res) => {
    const { email, username, password, firstName, lastName } = req.body;

    // Check if user already exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      throw new ConflictError('User with this email already exists');
    }

    // Create new user
    const user = await User.create({
      email,
      username,
      password,
      first_name: firstName,
      last_name: lastName
    });

    logger.info('User registered successfully', { 
      userId: user.id, 
      email: user.email,
      requestId: req.requestId 
    });

    // Generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Store refresh token
    await user.storeRefreshToken(refreshToken);

    res.status(201).json({
      success: true,
      data: {
        message: 'Registration successful',
        user: user.toSafeObject(),
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: config.jwt.accessExpiresIn
        }
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     tags: [Authentication]
 *     summary: Authenticate user and get JWT tokens
 *     description: |
 *       Authenticate a user with email/password and optionally 2FA token.
 *       Returns JWT access and refresh tokens for subsequent API calls.
 *       
 *       ### Authentication Flow:
 *       1. **Basic Auth**: Email + Password
 *       2. **2FA** (if enabled): TOTP token or backup code
 *       3. **Account Security**: Automatic lockout after failed attempts
 *       
 *       ### Security Features:
 *       - Rate limiting (5 attempts per 15 minutes)
 *       - Account lockout protection
 *       - 2FA support
 *       - Session management
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "john.doe@example.com"
 *                 description: User's registered email address
 *               password:
 *                 type: string
 *                 example: "SecurePass123!"
 *                 description: User's password
 *               twoFactorToken:
 *                 type: string
 *                 pattern: "^[0-9]{6}$"
 *                 example: "123456"
 *                 description: 6-digit TOTP token (required if 2FA enabled)
 *               backupCode:
 *                 type: string
 *                 example: "ABC123DEF456"
 *                 description: Backup code (alternative to TOTP)
 *               rememberMe:
 *                 type: boolean
 *                 default: false
 *                 example: true
 *                 description: Extend token validity (extends refresh token lifetime)
 *           examples:
 *             basicLogin:
 *               summary: Basic login (no 2FA)
 *               value:
 *                 email: "john.doe@example.com"
 *                 password: "SecurePass123!"
 *                 rememberMe: false
 *             loginWith2FA:
 *               summary: Login with 2FA token
 *               value:
 *                 email: "admin@example.com"
 *                 password: "AdminPass123!"
 *                 twoFactorToken: "123456"
 *                 rememberMe: true
 *             loginWithBackup:
 *               summary: Login with backup code
 *               value:
 *                 email: "user@example.com"
 *                 password: "UserPass123!"
 *                 backupCode: "ABC123DEF456"
 *     responses:
 *       '200':
 *         description: Login successful or 2FA required
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: true
 *                     data:
 *                       type: object
 *                       properties:
 *                         message:
 *                           type: string
 *                           example: "Login successful"
 *                         user:
 *                           $ref: '#/components/schemas/User'
 *                         tokens:
 *                           $ref: '#/components/schemas/JWTTokens'
 *                 - type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: true
 *                     data:
 *                       type: object
 *                       properties:
 *                         requiresTwoFactor:
 *                           type: boolean
 *                           example: true
 *                         message:
 *                           type: string
 *                           example: "2FA verification required"
 *                         userId:
 *                           type: string
 *                           format: uuid
 *             examples:
 *               successLogin:
 *                 summary: Successful login with tokens
 *                 value:
 *                   success: true
 *                   data:
 *                     message: "Login successful"
 *                     user:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       email: "john.doe@example.com"
 *                       username: "johndoe"
 *                       firstName: "John"
 *                       lastName: "Doe"
 *                       status: "active"
 *                       emailVerified: true
 *                       twoFactorEnabled: false
 *                       lastLogin: "2025-01-15T10:30:00.000Z"
 *                     tokens:
 *                       accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                       refreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                       expiresIn: "15m"
 *                       tokenType: "Bearer"
 *               requires2FA:
 *                 summary: 2FA verification required
 *                 value:
 *                   success: true
 *                   data:
 *                     requiresTwoFactor: true
 *                     message: "2FA verification required"
 *                     userId: "123e4567-e89b-12d3-a456-426614174000"
 *       '400':
 *         $ref: '#/components/responses/ValidationError'
 *       '401':
 *         description: Authentication failed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Invalid email or password"
 *                 code:
 *                   type: string
 *                   example: "INVALID_CREDENTIALS"
 *             examples:
 *               invalidCredentials:
 *                 summary: Invalid email or password
 *                 value:
 *                   success: false
 *                   message: "Invalid email or password"
 *                   code: "INVALID_CREDENTIALS"
 *               accountLocked:
 *                 summary: Account locked due to failed attempts
 *                 value:
 *                   success: false
 *                   message: "Account is locked. Try again in 15 minutes."
 *                   code: "ACCOUNT_LOCKED"
 *               invalid2FA:
 *                 summary: Invalid 2FA token
 *                 value:
 *                   success: false
 *                   message: "Invalid 2FA token or backup code"
 *                   code: "INVALID_2FA"
 *       '429':
 *         $ref: '#/components/responses/RateLimit'
 *       '500':
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/login',
  authRateLimit,
  validateBody(loginSchema),
  asyncHandler(async (req, res) => {
    const { email, password, rememberMe, twoFactorToken, backupCode } = req.body;

    // Find user by email
    const user = await User.findByEmail(email);
    if (!user) {
      throw new UnauthorizedError('Invalid email or password');
    }

    // Check if account is locked
    if (user.isLocked()) {
      const lockTime = new Date(user.locked_until);
      const remainingTime = Math.ceil((lockTime - new Date()) / 1000 / 60);
      throw new UnauthorizedError(`Account is locked. Try again in ${remainingTime} minutes.`);
    }

    // Verify password
    const isPasswordValid = await user.verifyPassword(password);
    if (!isPasswordValid) {
      await user.recordFailedLogin();
      throw new UnauthorizedError('Invalid email or password');
    }

    // Check 2FA if enabled
    if (user.two_factor_enabled) {
      let twoFactorValid = false;

      if (twoFactorToken) {
        twoFactorValid = await user.verify2FA(twoFactorToken);
      } else if (backupCode) {
        twoFactorValid = await user.useBackupCode(backupCode);
      }

      if (!twoFactorValid) {
        if (!twoFactorToken && !backupCode) {
          return res.status(200).json({
            success: true,
            data: {
              requiresTwoFactor: true,
              message: '2FA verification required',
              userId: user.id
            }
          });
        } else {
          await user.recordFailedLogin();
          throw new UnauthorizedError('Invalid 2FA token or backup code');
        }
      }
    }

    // Reset failed login attempts on successful login
    await user.resetFailedLogins();

    // Generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Store refresh token with extended expiration if "remember me"
    await user.storeRefreshToken(refreshToken);

    logger.info('User logged in successfully', { 
      userId: user.id, 
      email: user.email,
      twoFactorUsed: user.two_factor_enabled,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: 'Login successful',
        user: user.toSafeObject(),
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: config.jwt.accessExpiresIn
        }
      }
    });
  })
);

/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post('/refresh',
  validateBody(refreshTokenSchema),
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    // Verify refresh token
    const decoded = await User.verifyRefreshToken(refreshToken);
    
    // Get user
    const user = await User.findById(decoded.id);
    if (!user || user.status !== 'active') {
      throw new UnauthorizedError('Invalid refresh token');
    }

    // Generate new access token
    const newAccessToken = user.generateAccessToken();

    logger.debug('Access token refreshed', { 
      userId: user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        accessToken: newAccessToken,
        expiresIn: config.jwt.accessExpiresIn
      }
    });
  })
);

/**
 * @route   POST /auth/logout
 * @desc    Logout user and invalidate tokens
 * @access  Private
 */
router.post('/logout',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    // Blacklist access token
    await blacklistToken(req.token);

    // Revoke refresh token if provided
    if (refreshToken) {
      try {
        await req.user.revokeRefreshToken(refreshToken);
      } catch (error) {
        logger.warn('Failed to revoke refresh token during logout', { 
          userId: req.user.id,
          error: error.message 
        });
      }
    }

    logger.info('User logged out', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: 'Logout successful'
      }
    });
  })
);

/**
 * @route   POST /auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all',
  authenticateToken,
  require2FA,
  asyncHandler(async (req, res) => {
    // Blacklist current access token
    await blacklistToken(req.token);

    // Revoke all refresh tokens
    await req.user.revokeAllRefreshTokens();

    logger.info('User logged out from all devices', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: 'Logged out from all devices successfully'
      }
    });
  })
);

/**
 * @route   GET /auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me',
  authenticateToken,
  asyncHandler(async (req, res) => {
    res.json({
      success: true,
      data: {
        user: req.user.toSafeObject()
      }
    });
  })
);

/**
 * @route   POST /auth/2fa/setup
 * @desc    Setup 2FA for user account
 * @access  Private
 */
router.post('/2fa/setup',
  authenticateToken,
  asyncHandler(async (req, res) => {
    if (req.user.two_factor_enabled) {
      throw new ConflictError('2FA is already enabled for this account');
    }

    // Generate 2FA secret and QR code
    const setup = await req.user.setup2FA();

    // Generate QR code as data URL
    const qrCodeDataURL = await qrcode.toDataURL(setup.qrCode);

    logger.info('2FA setup initiated', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: '2FA setup initiated. Scan the QR code with your authenticator app.',
        qrCode: qrCodeDataURL,
        manualEntryKey: setup.manualEntryKey,
        backupCodes: null // Will be provided after verification
      }
    });
  })
);

/**
 * @route   POST /auth/2fa/verify-setup
 * @desc    Verify and activate 2FA setup
 * @access  Private
 */
router.post('/2fa/verify-setup',
  authenticateToken,
  validateBody(setup2FASchema),
  asyncHandler(async (req, res) => {
    const { twoFactorToken } = req.body;

    if (req.user.two_factor_enabled) {
      throw new ConflictError('2FA is already enabled for this account');
    }

    // Verify 2FA token and activate
    const isValid = await req.user.verify2FA(twoFactorToken, true);
    
    if (!isValid) {
      throw new UnauthorizedError('Invalid 2FA token');
    }

    // Get backup codes (generated during activation)
    const backupCodes = req.user.backup_codes;

    logger.info('2FA activated successfully', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: '2FA has been successfully enabled for your account',
        backupCodes,
        warning: 'Save these backup codes in a secure location. They can only be used once each.'
      }
    });
  })
);

/**
 * @route   POST /auth/2fa/verify
 * @desc    Verify 2FA token for current session
 * @access  Private
 */
router.post('/2fa/verify',
  authenticateToken,
  validateBody(verify2FASchema),
  verify2FAToken,
  asyncHandler(async (req, res) => {
    logger.info('2FA verification completed', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: '2FA verification successful',
        verified: true
      }
    });
  })
);

/**
 * @route   POST /auth/2fa/disable
 * @desc    Disable 2FA for user account
 * @access  Private
 */
router.post('/2fa/disable',
  authenticateToken,
  require2FA,
  asyncHandler(async (req, res) => {
    if (!req.user.two_factor_enabled) {
      throw new ConflictError('2FA is not enabled for this account');
    }

    await req.user.disable2FA();

    logger.info('2FA disabled', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: '2FA has been disabled for your account'
      }
    });
  })
);

/**
 * @route   POST /auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password',
  authenticateToken,
  require2FA,
  validateBody(changePasswordSchema),
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // Verify current password
    const isCurrentPasswordValid = await req.user.verifyPassword(currentPassword);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedError('Current password is incorrect');
    }

    // Update password
    const bcrypt = await import('bcrypt');
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    const updateQuery = `
      UPDATE users 
      SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `;

    await query(updateQuery, [newPasswordHash, req.user.id]);

    // Revoke all refresh tokens to force re-login on other devices
    await req.user.revokeAllRefreshTokens();

    logger.info('Password changed successfully', { 
      userId: req.user.id,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: 'Password changed successfully. Please log in again on other devices.'
      }
    });
  })
);

/**
 * @route   POST /auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password',
  authRateLimit,
  validateBody(resetPasswordRequestSchema),
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findByEmail(email);
    
    // Always return success to prevent email enumeration attacks
    // Following Zero Trust principle: "never trust, always verify"
    if (!user) {
      logger.warn('Password reset requested for non-existent email', { 
        email,
        requestId: req.requestId 
      });
      
      return res.json({
        success: true,
        data: {
          message: 'If an account with that email exists, a password reset link has been sent.'
        }
      });
    }

    try {
      // Generate secure reset token
      const resetToken = await user.generatePasswordResetToken();
      
      // Import email service dynamically to avoid circular dependencies
      const { emailService } = await import('../services/EmailService.js');
      
      // Send password reset email
      await emailService.sendPasswordResetEmail(
        user.email, 
        resetToken, 
        user.first_name
      );

      // Log security event
      const { AuditLog } = await import('../models/AuditLog.js');
      await AuditLog.logSecurityEvent('PASSWORD_RESET_REQUESTED', req, {
        userId: user.id,
        email: user.email
      });

      logger.info('Password reset email sent', { 
        userId: user.id,
        email: user.email,
        requestId: req.requestId 
      });

    } catch (error) {
      logger.error('Error processing password reset request:', {
        error: error.message,
        email: user.email,
        requestId: req.requestId
      });
    }

    // Always return success regardless of outcome for security
    res.json({
      success: true,
      data: {
        message: 'If an account with that email exists, a password reset link has been sent.'
      }
    });
  })
);

/**
 * @route   POST /auth/reset-password
 * @desc    Reset password with valid token
 * @access  Public
 */
router.post('/reset-password',
  authRateLimit,
  validateBody(resetPasswordConfirmSchema),
  asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;

    try {
      // Verify reset token
      const user = await User.verifyPasswordResetToken(token);
      
      if (!user) {
        throw new UnauthorizedError('Invalid or expired reset token');
      }

      // Reset password
      await user.resetPassword(newPassword, token);

      // Import services
      const { emailService } = await import('../services/EmailService.js');
      const { AuditLog } = await import('../models/AuditLog.js');

      // Send security notification
      await emailService.sendSecurityAlert(
        user.email,
        'PASSWORD_CHANGED',
        {
          ip_address: req.ip,
          user_agent: req.get('User-Agent'),
          timestamp: new Date().toISOString()
        },
        user.first_name
      );

      // Log security event
      await AuditLog.logSecurityEvent('PASSWORD_RESET_COMPLETED', req, {
        userId: user.id,
        email: user.email,
        success: true
      });

      logger.info('Password reset completed', {
        userId: user.id,
        email: user.email,
        requestId: req.requestId
      });

      res.json({
        success: true,
        data: {
          message: 'Password has been reset successfully. Please log in with your new password.'
        }
      });

    } catch (error) {
      // Log failed attempt
      const { AuditLog } = await import('../models/AuditLog.js');
      await AuditLog.logSecurityEvent('PASSWORD_RESET_FAILED', req, {
        success: false,
        error: error.message,
        token: token.substring(0, 8) + '...'
      });

      logger.warn('Password reset attempt failed', {
        error: error.message,
        token: token.substring(0, 8) + '...',
        requestId: req.requestId
      });

      throw error;
    }
  })
);

/**
 * @route   GET /auth/status
 * @desc    Check authentication status
 * @access  Public
 */
router.get('/status',
  asyncHandler(async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.json({
        success: true,
        data: {
          authenticated: false,
          user: null
        }
      });
    }

    try {
      // Verify token without throwing errors
      const jwt = await import('jsonwebtoken');
      const decoded = jwt.verify(token, config.jwt.secret);
      
      const user = await User.findById(decoded.id);
      
      if (!user || !user.is_active) {
        return res.json({
          success: true,
          data: {
            authenticated: false,
            user: null
          }
        });
      }

      res.json({
        success: true,
        data: {
          authenticated: true,
          user: user.toSafeObject(),
          tokenValid: true
        }
      });
    } catch (error) {
      res.json({
        success: true,
        data: {
          authenticated: false,
          user: null,
          tokenValid: false
        }
      });
    }
  })
);

export default router; 
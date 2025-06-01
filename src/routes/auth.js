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
 * @route   POST /auth/register
 * @desc    Register a new user
 * @access  Public
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
 * @route   POST /auth/login
 * @desc    Authenticate user and return tokens
 * @access  Public
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
    if (!user || !user.is_active) {
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
    
    // Always return success to prevent email enumeration
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

    // Generate reset token (implement in next iteration)
    // For now, just log the request
    logger.info('Password reset requested', { 
      userId: user.id,
      email: user.email,
      requestId: req.requestId 
    });

    res.json({
      success: true,
      data: {
        message: 'If an account with that email exists, a password reset link has been sent.'
      }
    });
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
import Joi from 'joi';

/**
 * Authentication Validation Schemas
 * Following 2025 best practices for Node.js 20+ and Express.js
 */

/**
 * Common validation patterns
 */
const patterns = {
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  username: /^[a-zA-Z0-9_-]{3,30}$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  name: /^[a-zA-ZÀ-ÿ\s'-]{2,50}$/,
  twoFactorToken: /^\d{6}$/,
  backupCode: /^[A-F0-9]{8}$/
};

/**
 * Custom validation messages
 */
const messages = {
  'string.email': 'Please provide a valid email address',
  'string.pattern.base': 'Invalid format',
  'string.min': 'Must be at least {#limit} characters long',
  'string.max': 'Must not exceed {#limit} characters',
  'any.required': 'This field is required',
  'string.empty': 'This field cannot be empty'
};

/**
 * User registration schema
 */
export const registerSchema = Joi.object({
  email: Joi.string()
    .email()
    .pattern(patterns.email)
    .lowercase()
    .trim()
    .max(255)
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.pattern.base': 'Email format is invalid'
    }),

  username: Joi.string()
    .pattern(patterns.username)
    .lowercase()
    .trim()
    .min(3)
    .max(30)
    .required()
    .messages({
      'string.pattern.base': 'Username must contain only letters, numbers, underscores, and hyphens (3-30 characters)'
    }),

  password: Joi.string()
    .pattern(patterns.password)
    .min(8)
    .max(128)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least 8 characters with uppercase, lowercase, number, and special character'
    }),

  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match'
    }),

  firstName: Joi.string()
    .pattern(patterns.name)
    .trim()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.pattern.base': 'First name must contain only letters, spaces, apostrophes, and hyphens'
    }),

  lastName: Joi.string()
    .pattern(patterns.name)
    .trim()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.pattern.base': 'Last name must contain only letters, spaces, apostrophes, and hyphens'
    }),

  acceptTerms: Joi.boolean()
    .valid(true)
    .required()
    .messages({
      'any.only': 'You must accept the terms and conditions'
    })
}).options({ 
  stripUnknown: true,
  abortEarly: false,
  messages 
});

/**
 * User login schema
 */
export const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .lowercase()
    .trim()
    .required(),

  password: Joi.string()
    .min(1)
    .max(128)
    .required(),

  rememberMe: Joi.boolean()
    .default(false),

  twoFactorToken: Joi.string()
    .pattern(patterns.twoFactorToken)
    .optional()
    .messages({
      'string.pattern.base': '2FA token must be 6 digits'
    }),

  backupCode: Joi.string()
    .pattern(patterns.backupCode)
    .uppercase()
    .optional()
    .messages({
      'string.pattern.base': 'Backup code must be 8 hexadecimal characters'
    })
}).options({ 
  stripUnknown: true,
  abortEarly: false,
  messages 
});

/**
 * Refresh token schema
 */
export const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string()
    .required()
    .messages({
      'any.required': 'Refresh token is required'
    })
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * 2FA setup verification schema
 */
export const setup2FASchema = Joi.object({
  twoFactorToken: Joi.string()
    .pattern(patterns.twoFactorToken)
    .required()
    .messages({
      'string.pattern.base': '2FA token must be 6 digits',
      'any.required': '2FA token is required to complete setup'
    })
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * 2FA verification schema
 */
export const verify2FASchema = Joi.object({
  twoFactorToken: Joi.string()
    .pattern(patterns.twoFactorToken)
    .optional()
    .messages({
      'string.pattern.base': '2FA token must be 6 digits'
    }),

  backupCode: Joi.string()
    .pattern(patterns.backupCode)
    .uppercase()
    .optional()
    .messages({
      'string.pattern.base': 'Backup code must be 8 hexadecimal characters'
    })
}).or('twoFactorToken', 'backupCode')
  .options({ 
    stripUnknown: true,
    messages: {
      ...messages,
      'object.missing': 'Either 2FA token or backup code is required'
    }
  });

/**
 * Password change schema
 */
export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string()
    .min(1)
    .max(128)
    .required()
    .messages({
      'any.required': 'Current password is required'
    }),

  newPassword: Joi.string()
    .pattern(patterns.password)
    .min(8)
    .max(128)
    .invalid(Joi.ref('currentPassword'))
    .required()
    .messages({
      'string.pattern.base': 'New password must contain at least 8 characters with uppercase, lowercase, number, and special character',
      'any.invalid': 'New password must be different from current password'
    }),

  confirmNewPassword: Joi.string()
    .valid(Joi.ref('newPassword'))
    .required()
    .messages({
      'any.only': 'Password confirmation does not match new password'
    })
}).options({ 
  stripUnknown: true,
  abortEarly: false,
  messages 
});

/**
 * Password reset request schema
 */
export const resetPasswordRequestSchema = Joi.object({
  email: Joi.string()
    .email()
    .lowercase()
    .trim()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address'
    })
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * Password reset confirmation schema
 */
export const resetPasswordConfirmSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'any.required': 'Reset token is required'
    }),

  newPassword: Joi.string()
    .pattern(patterns.password)
    .min(8)
    .max(128)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least 8 characters with uppercase, lowercase, number, and special character'
    }),

  confirmNewPassword: Joi.string()
    .valid(Joi.ref('newPassword'))
    .required()
    .messages({
      'any.only': 'Password confirmation does not match new password'
    })
}).options({ 
  stripUnknown: true,
  abortEarly: false,
  messages 
});

/**
 * Email verification schema
 */
export const verifyEmailSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'any.required': 'Verification token is required'
    })
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * Resend verification email schema
 */
export const resendVerificationSchema = Joi.object({
  email: Joi.string()
    .email()
    .lowercase()
    .trim()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address'
    })
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * Update profile schema
 */
export const updateProfileSchema = Joi.object({
  firstName: Joi.string()
    .pattern(patterns.name)
    .trim()
    .min(2)
    .max(50)
    .optional()
    .messages({
      'string.pattern.base': 'First name must contain only letters, spaces, apostrophes, and hyphens'
    }),

  lastName: Joi.string()
    .pattern(patterns.name)
    .trim()
    .min(2)
    .max(50)
    .optional()
    .messages({
      'string.pattern.base': 'Last name must contain only letters, spaces, apostrophes, and hyphens'
    }),

  username: Joi.string()
    .pattern(patterns.username)
    .lowercase()
    .trim()
    .min(3)
    .max(30)
    .optional()
    .messages({
      'string.pattern.base': 'Username must contain only letters, numbers, underscores, and hyphens (3-30 characters)'
    })
}).min(1)
  .options({ 
    stripUnknown: true,
    abortEarly: false,
    messages: {
      ...messages,
      'object.min': 'At least one field must be provided for update'
    }
  });

/**
 * Query parameter schemas
 */
export const paginationSchema = Joi.object({
  page: Joi.number()
    .integer()
    .min(1)
    .default(1),

  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(20),

  sort: Joi.string()
    .valid('created_at', 'updated_at', 'email', 'username', 'last_login')
    .default('created_at'),

  order: Joi.string()
    .valid('asc', 'desc')
    .default('desc')
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * Search schema
 */
export const searchSchema = Joi.object({
  q: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .optional(),

  filter: Joi.string()
    .valid('active', 'inactive', 'verified', 'unverified', '2fa_enabled', '2fa_disabled')
    .optional()
}).options({ 
  stripUnknown: true,
  messages 
});

/**
 * Validation helper functions
 */
export const validateBody = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body);
    
    if (error) {
      const details = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));
      
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details,
          timestamp: new Date().toISOString()
        }
      });
    }
    
    req.body = value;
    next();
  };
};

export const validateQuery = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query);
    
    if (error) {
      const details = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));
      
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Query validation failed',
          details,
          timestamp: new Date().toISOString()
        }
      });
    }
    
    req.query = value;
    next();
  };
};

export const validateParams = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.params);
    
    if (error) {
      const details = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));
      
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Parameter validation failed',
          details,
          timestamp: new Date().toISOString()
        }
      });
    }
    
    req.params = value;
    next();
  };
};

export default {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  setup2FASchema,
  verify2FASchema,
  changePasswordSchema,
  resetPasswordRequestSchema,
  resetPasswordConfirmSchema,
  verifyEmailSchema,
  resendVerificationSchema,
  updateProfileSchema,
  paginationSchema,
  searchSchema,
  validateBody,
  validateQuery,
  validateParams
}; 
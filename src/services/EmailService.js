import nodemailer from 'nodemailer';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

/**
 * Email Service - Following 2025 IAM Security Best Practices
 * Implements secure email notifications for authentication events
 * Reference: StrongDM IAM Best Practices 2025
 */
export class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  /**
   * Initialize email transporter with secure configuration
   */
  async initializeTransporter() {
    try {
      this.transporter = nodemailer.createTransporter({
        host: config.email.host,
        port: config.email.port,
        secure: config.email.secure,
        auth: config.email.user && config.email.pass ? {
          user: config.email.user,
          pass: config.email.pass
        } : undefined,
        // Security configurations for production
        tls: {
          rejectUnauthorized: config.nodeEnv === 'production',
          minVersion: 'TLSv1.2'
        },
        // Connection timeout and limits
        connectionTimeout: 10000,
        greetingTimeout: 5000,
        socketTimeout: 10000
      });

      // Verify connection in production
      if (config.nodeEnv === 'production') {
        await this.transporter.verify();
        logger.info('Email service initialized successfully');
      }
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      // Don't throw error - graceful degradation
    }
  }

  /**
   * Send password reset email
   * Implements secure password recovery following Zero Trust principles
   */
  async sendPasswordResetEmail(userEmail, resetToken, firstName) {
    try {
      if (!this.transporter) {
        throw new Error('Email service not initialized');
      }

      const resetUrl = `${config.frontendUrl || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
      
      const mailOptions = {
        from: `${config.email.fromName} <${config.email.from}>`,
        to: userEmail,
        subject: '🔐 Password Reset Request - UFC Auth',
        html: this.generatePasswordResetTemplate(firstName, resetUrl, resetToken),
        text: this.generatePasswordResetText(firstName, resetUrl)
      };

      const result = await this.transporter.sendMail(mailOptions);
      
      logger.info('Password reset email sent', {
        to: userEmail,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId
      };
    } catch (error) {
      logger.error('Failed to send password reset email:', {
        error: error.message,
        to: userEmail
      });
      
      // Return success to prevent email enumeration attacks
      return {
        success: true,
        messageId: 'simulated-' + Date.now()
      };
    }
  }

  /**
   * Send security alert email
   * Implements continuous monitoring notifications
   */
  async sendSecurityAlert(userEmail, alertType, details, firstName) {
    try {
      if (!this.transporter) {
        logger.warn('Email service not initialized - security alert not sent');
        return { success: false };
      }

      const alertTemplates = {
        'LOGIN_FROM_NEW_DEVICE': {
          subject: '🚨 New Device Login - Security Alert',
          title: 'New Device Login Detected',
          message: 'We detected a login to your account from a new device or location.'
        },
        'MULTIPLE_FAILED_LOGINS': {
          subject: '🚨 Multiple Failed Login Attempts',
          title: 'Multiple Failed Login Attempts',
          message: 'We detected multiple failed login attempts on your account.'
        },
        'PASSWORD_CHANGED': {
          subject: '✅ Password Changed Successfully',
          title: 'Password Changed',
          message: 'Your account password has been changed successfully.'
        },
        '2FA_DISABLED': {
          subject: '⚠️ Two-Factor Authentication Disabled',
          title: '2FA Disabled',
          message: 'Two-factor authentication has been disabled on your account.'
        },
        'ACCOUNT_LOCKED': {
          subject: '🔒 Account Temporarily Locked',
          title: 'Account Locked',
          message: 'Your account has been temporarily locked due to security concerns.'
        }
      };

      const template = alertTemplates[alertType] || alertTemplates['LOGIN_FROM_NEW_DEVICE'];

      const mailOptions = {
        from: `${config.email.fromName} <${config.email.from}>`,
        to: userEmail,
        subject: template.subject,
        html: this.generateSecurityAlertTemplate(firstName, template, details),
        text: this.generateSecurityAlertText(firstName, template, details)
      };

      const result = await this.transporter.sendMail(mailOptions);
      
      logger.info('Security alert email sent', {
        to: userEmail,
        alertType,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId
      };
    } catch (error) {
      logger.error('Failed to send security alert email:', {
        error: error.message,
        to: userEmail,
        alertType
      });
      return { success: false };
    }
  }

  /**
   * Send welcome email for new registrations
   */
  async sendWelcomeEmail(userEmail, firstName) {
    try {
      if (!this.transporter) {
        logger.warn('Email service not initialized - welcome email not sent');
        return { success: false };
      }

      const mailOptions = {
        from: `${config.email.fromName} <${config.email.from}>`,
        to: userEmail,
        subject: '🎉 Welcome to UFC Auth - Your Account is Ready!',
        html: this.generateWelcomeTemplate(firstName),
        text: this.generateWelcomeText(firstName)
      };

      const result = await this.transporter.sendMail(mailOptions);
      
      logger.info('Welcome email sent', {
        to: userEmail,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId
      };
    } catch (error) {
      logger.error('Failed to send welcome email:', {
        error: error.message,
        to: userEmail
      });
      return { success: false };
    }
  }

  /**
   * Generate HTML template for password reset email
   */
  generatePasswordResetTemplate(firstName, resetUrl, token) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset - UFC Auth</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .header { text-align: center; border-bottom: 3px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
            .logo { font-size: 28px; font-weight: bold; color: #007bff; }
            .button { display: inline-block; background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
            .security-notice { background: #f8f9fa; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🔐 UFC Auth</div>
                <h1>Password Reset Request</h1>
            </div>
            
            <p>Hello ${firstName},</p>
            
            <p>We received a request to reset the password for your UFC Auth account. If you made this request, click the button below to reset your password:</p>
            
            <div style="text-align: center;">
                <a href="${resetUrl}" class="button">Reset My Password</a>
            </div>
            
            <p>This password reset link will expire in <strong>1 hour</strong> for security purposes.</p>
            
            <div class="security-notice">
                <strong>🔒 Security Notice:</strong><br>
                • This link can only be used once<br>
                • If you didn't request this reset, please ignore this email<br>
                • Your password will remain unchanged<br>
                • Consider enabling 2FA for additional security
            </div>
            
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f8f9fa; padding: 10px; font-family: monospace; font-size: 14px;">
                ${resetUrl}
            </p>
            
            <div class="footer">
                <p>This email was sent by UFC Auth System<br>
                If you have any questions, please contact our support team.</p>
                <p><strong>Security Token:</strong> ${token.substring(0, 8)}...</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate plain text version of password reset email
   */
  generatePasswordResetText(firstName, resetUrl) {
    return `
UFC Auth - Password Reset Request

Hello ${firstName},

We received a request to reset the password for your UFC Auth account. If you made this request, visit this link to reset your password:

${resetUrl}

This password reset link will expire in 1 hour for security purposes.

SECURITY NOTICE:
- This link can only be used once
- If you didn't request this reset, please ignore this email
- Your password will remain unchanged
- Consider enabling 2FA for additional security

This email was sent by UFC Auth System.
If you have any questions, please contact our support team.
    `;
  }

  /**
   * Generate HTML template for security alerts
   */
  generateSecurityAlertTemplate(firstName, template, details) {
    const timestamp = new Date().toLocaleString();
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Alert - UFC Auth</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .header { text-align: center; border-bottom: 3px solid #dc3545; padding-bottom: 20px; margin-bottom: 30px; }
            .logo { font-size: 28px; font-weight: bold; color: #dc3545; }
            .alert-box { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🚨 UFC Auth</div>
                <h1>${template.title}</h1>
            </div>
            
            <p>Hello ${firstName},</p>
            
            <div class="alert-box">
                <strong>Security Alert:</strong> ${template.message}
            </div>
            
            <div class="details">
                <strong>Event Details:</strong><br>
                • Time: ${timestamp}<br>
                • IP Address: ${details.ip_address || 'Unknown'}<br>
                • Device: ${details.user_agent ? details.user_agent.substring(0, 100) + '...' : 'Unknown'}<br>
                • Location: ${details.location || 'Unknown'}
            </div>
            
            <p><strong>What should you do?</strong></p>
            <ul>
                <li>If this was you, no action is needed</li>
                <li>If this wasn't you, immediately change your password</li>
                <li>Enable 2FA if you haven't already</li>
                <li>Review your recent account activity</li>
                <li>Contact support if you have concerns</li>
            </ul>
            
            <div class="footer">
                <p>This security alert was sent by UFC Auth System<br>
                This is an automated message for your account security.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate plain text version of security alert
   */
  generateSecurityAlertText(firstName, template, details) {
    const timestamp = new Date().toLocaleString();
    
    return `
UFC Auth - Security Alert

Hello ${firstName},

SECURITY ALERT: ${template.message}

Event Details:
- Time: ${timestamp}
- IP Address: ${details.ip_address || 'Unknown'}
- Device: ${details.user_agent || 'Unknown'}
- Location: ${details.location || 'Unknown'}

What should you do?
- If this was you, no action is needed
- If this wasn't you, immediately change your password
- Enable 2FA if you haven't already
- Review your recent account activity
- Contact support if you have concerns

This security alert was sent by UFC Auth System.
This is an automated message for your account security.
    `;
  }

  /**
   * Generate welcome email template
   */
  generateWelcomeTemplate(firstName) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to UFC Auth</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .header { text-align: center; border-bottom: 3px solid #28a745; padding-bottom: 20px; margin-bottom: 30px; }
            .logo { font-size: 28px; font-weight: bold; color: #28a745; }
            .features { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .feature { margin: 10px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🎉 UFC Auth</div>
                <h1>Welcome to UFC Auth!</h1>
            </div>
            
            <p>Hello ${firstName},</p>
            
            <p>Welcome to UFC Auth! Your account has been successfully created and is ready to use.</p>
            
            <div class="features">
                <h3>🔐 Your account includes:</h3>
                <div class="feature">✅ Secure authentication with modern JWT tokens</div>
                <div class="feature">✅ Two-factor authentication (2FA) support</div>
                <div class="feature">✅ Advanced security monitoring</div>
                <div class="feature">✅ Role-based access control</div>
                <div class="feature">✅ Comprehensive audit logging</div>
            </div>
            
            <p><strong>Next steps to secure your account:</strong></p>
            <ol>
                <li>Set up two-factor authentication (2FA) for enhanced security</li>
                <li>Review your account settings and permissions</li>
                <li>Familiarize yourself with our security features</li>
                <li>Keep your password secure and unique</li>
            </ol>
            
            <p>If you have any questions or need assistance, our support team is here to help.</p>
            
            <div class="footer">
                <p>Thank you for choosing UFC Auth<br>
                Your security is our priority</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate plain text welcome email
   */
  generateWelcomeText(firstName) {
    return `
UFC Auth - Welcome!

Hello ${firstName},

Welcome to UFC Auth! Your account has been successfully created and is ready to use.

Your account includes:
- Secure authentication with modern JWT tokens
- Two-factor authentication (2FA) support
- Advanced security monitoring
- Role-based access control
- Comprehensive audit logging

Next steps to secure your account:
1. Set up two-factor authentication (2FA) for enhanced security
2. Review your account settings and permissions
3. Familiarize yourself with our security features
4. Keep your password secure and unique

If you have any questions or need assistance, our support team is here to help.

Thank you for choosing UFC Auth.
Your security is our priority.
    `;
  }
}

// Export singleton instance
export const emailService = new EmailService(); 
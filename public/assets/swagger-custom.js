/**
 * UFC Auth API - Custom Swagger UI Enhancements
 * Following 2025 UI/UX best practices for API documentation
 */

(function() {
  'use strict';

  // Wait for Swagger UI to load
  document.addEventListener('DOMContentLoaded', function() {
    
    // Custom authentication helper
    function enhanceAuthentication() {
      // Add custom authentication instructions
      const authSection = document.querySelector('.auth-wrapper');
      if (authSection) {
        const helpText = document.createElement('div');
        helpText.className = 'auth-help';
        helpText.innerHTML = `
          <div style="background: #f8fafc; padding: 16px; border-radius: 8px; margin: 16px 0; border-left: 4px solid #3b82f6;">
            <h4 style="margin: 0 0 8px 0; color: #1f2937;">🔐 Quick Authentication Guide</h4>
            <p style="margin: 0; color: #6b7280; font-size: 14px;">
              1. <strong>Register</strong> a new account or use existing credentials<br>
              2. <strong>Login</strong> to get your access token<br>
              3. <strong>Copy</strong> the access token from the login response<br>
              4. <strong>Click "Authorize"</strong> and paste the token<br>
              5. <strong>Test</strong> protected endpoints!
            </p>
          </div>
        `;
        authSection.appendChild(helpText);
      }
    }

    // Add response time tracking
    function addResponseTimeTracking() {
      const originalFetch = window.fetch;
      window.fetch = function(...args) {
        const startTime = performance.now();
        return originalFetch.apply(this, args).then(response => {
          const endTime = performance.now();
          const duration = Math.round(endTime - startTime);
          
          // Add response time to console for debugging
          console.log(`🚀 API Response: ${response.status} ${response.url.split('/').pop()} (${duration}ms)`);
          
          return response;
        });
      };
    }

    // Enhance error display
    function enhanceErrorDisplay() {
      // Monitor for error responses and enhance display
      const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          mutation.addedNodes.forEach(function(node) {
            if (node.nodeType === 1 && node.classList && node.classList.contains('response')) {
              const statusElement = node.querySelector('.response-col_status');
              if (statusElement) {
                const status = statusElement.textContent.trim();
                if (status.startsWith('4') || status.startsWith('5')) {
                  // Add error styling
                  node.style.borderLeft = '4px solid #ef4444';
                  node.style.backgroundColor = '#fef2f2';
                }
              }
            }
          });
        });
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }

    // Add custom CSS for better UX
    function injectCustomStyles() {
      const style = document.createElement('style');
      style.textContent = `
        /* Custom enhancements for UFC Auth API docs */
        .swagger-ui .info .title::after {
          content: " 🛡️";
          font-size: 0.8em;
        }
        
        .swagger-ui .auth-wrapper .btn.authorize {
          background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
          border: none;
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
          transition: all 0.2s ease;
        }
        
        .swagger-ui .auth-wrapper .btn.authorize:hover {
          transform: translateY(-1px);
          box-shadow: 0 6px 12px -1px rgba(0, 0, 0, 0.15);
        }
        
        .swagger-ui .opblock-summary-description {
          font-weight: 500;
        }
        
        .swagger-ui .opblock-description-wrapper {
          background: #f8fafc;
          border-radius: 6px;
          padding: 16px;
          margin: 12px 0;
        }
        
        .swagger-ui .response-col_status {
          font-weight: 600;
        }
        
        /* Status code colors */
        .swagger-ui .response-col_status:contains("200"),
        .swagger-ui .response-col_status:contains("201") {
          color: #059669;
        }
        
        .swagger-ui .response-col_status:contains("400"),
        .swagger-ui .response-col_status:contains("401"),
        .swagger-ui .response-col_status:contains("403"),
        .swagger-ui .response-col_status:contains("404") {
          color: #dc2626;
        }
        
        /* Custom badge for security requirements */
        .swagger-ui .opblock-tag {
          position: relative;
        }
        
        .swagger-ui .opblock[data-tag="Authentication"] .opblock-tag::after {
          content: "🔐";
          margin-left: 8px;
        }
        
        .swagger-ui .opblock[data-tag="RBAC"] .opblock-tag::after {
          content: "🛡️";
          margin-left: 8px;
        }
        
        .swagger-ui .opblock[data-tag="Audit"] .opblock-tag::after {
          content: "📊";
          margin-left: 8px;
        }
        
        .swagger-ui .opblock[data-tag="System"] .opblock-tag::after {
          content: "⚙️";
          margin-left: 8px;
        }
        
        /* Enhance try-it-out buttons */
        .swagger-ui .btn.try-out__btn {
          background: #10b981;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 8px 16px;
          font-weight: 500;
          transition: all 0.2s ease;
        }
        
        .swagger-ui .btn.try-out__btn:hover {
          background: #059669;
          transform: translateY(-1px);
        }
        
        /* Response highlighting */
        .swagger-ui .highlight-code {
          background: #f1f5f9;
          border-radius: 6px;
          border: 1px solid #e2e8f0;
        }
        
        /* Loading states */
        .swagger-ui .loading {
          position: relative;
        }
        
        .swagger-ui .loading::after {
          content: "";
          position: absolute;
          top: 50%;
          left: 50%;
          width: 20px;
          height: 20px;
          margin: -10px 0 0 -10px;
          border: 2px solid #e2e8f0;
          border-top: 2px solid #3b82f6;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }

    // Add helpful tooltips
    function addTooltips() {
      // Add tooltips to common elements
      const tooltips = [
        { selector: '.authorize', text: 'Click here to authenticate with your JWT token' },
        { selector: '.try-out__btn', text: 'Test this endpoint with real data' },
        { selector: '.response-col_status', text: 'HTTP status code - hover for details' }
      ];

      tooltips.forEach(tooltip => {
        document.querySelectorAll(tooltip.selector).forEach(element => {
          element.title = tooltip.text;
        });
      });
    }

    // Initialize enhancements
    function initializeEnhancements() {
      setTimeout(() => {
        enhanceAuthentication();
        addResponseTimeTracking();
        enhanceErrorDisplay();
        injectCustomStyles();
        addTooltips();
        
        console.log('🎨 UFC Auth API Documentation enhanced with 2025 best practices');
      }, 1000);
    }

    // Auto-collapse less important sections
    function autoCollapseSections() {
      setTimeout(() => {
        // Collapse System endpoints by default (keep auth visible)
        const systemSection = document.querySelector('[data-tag="System"]');
        if (systemSection) {
          const collapseBtn = systemSection.querySelector('.opblock-tag');
          if (collapseBtn && !systemSection.classList.contains('is-open')) {
            // Let System section stay collapsed by default
          }
        }
      }, 1500);
    }

    // Add keyboard shortcuts
    function addKeyboardShortcuts() {
      document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
          e.preventDefault();
          const searchInput = document.querySelector('.filter input');
          if (searchInput) {
            searchInput.focus();
          }
        }
        
        // Escape to clear search
        if (e.key === 'Escape') {
          const searchInput = document.querySelector('.filter input');
          if (searchInput && searchInput.value) {
            searchInput.value = '';
            searchInput.dispatchEvent(new Event('input'));
          }
        }
      });
    }

    // Add footer with additional info
    function addCustomFooter() {
      setTimeout(() => {
        const infoSection = document.querySelector('.swagger-ui .info');
        if (infoSection && !document.querySelector('.custom-footer')) {
          const footer = document.createElement('div');
          footer.className = 'custom-footer';
          footer.innerHTML = `
            <div style="background: #f8fafc; border-radius: 8px; padding: 20px; margin: 20px 0; border: 1px solid #e2e8f0;">
              <h3 style="margin: 0 0 12px 0; color: #1f2937;">🚀 Quick Start Guide</h3>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
                <div>
                  <h4 style="margin: 0 0 8px 0; color: #374151;">1. Authentication</h4>
                  <p style="margin: 0; color: #6b7280; font-size: 14px;">Register → Login → Copy Token → Authorize</p>
                </div>
                <div>
                  <h4 style="margin: 0 0 8px 0; color: #374151;">2. Rate Limits</h4>
                  <p style="margin: 0; color: #6b7280; font-size: 14px;">100 requests/15min globally, 5 login attempts/15min</p>
                </div>
                <div>
                  <h4 style="margin: 0 0 8px 0; color: #374151;">3. 2FA Setup</h4>
                  <p style="margin: 0; color: #6b7280; font-size: 14px;">Use /auth/2fa/setup after login for enhanced security</p>
                </div>
              </div>
              <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e2e8f0;">
                <p style="margin: 0; color: #6b7280; font-size: 12px;">
                  💡 <strong>Tip:</strong> Use Ctrl+K to search endpoints, ESC to clear search. All endpoints require HTTPS in production.
                </p>
              </div>
            </div>
          `;
          infoSection.appendChild(footer);
        }
      }, 2000);
    }

    // Initialize all enhancements
    initializeEnhancements();
    autoCollapseSections();
    addKeyboardShortcuts();
    addCustomFooter();

    // Re-run enhancements when content changes (for SPA behavior)
    const observer = new MutationObserver(function(mutations) {
      let shouldReEnhance = false;
      mutations.forEach(function(mutation) {
        if (mutation.addedNodes.length > 0) {
          shouldReEnhance = true;
        }
      });
      
      if (shouldReEnhance) {
        setTimeout(addTooltips, 500);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  });

})(); 
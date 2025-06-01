# syntax=docker/dockerfile:1.4

# Use specific Node.js LTS version instead of 'latest'
FROM node:20-alpine AS base

# Install security updates and dumb-init for proper signal handling
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create app directory and non-root user
WORKDIR /usr/src/app
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001

# Development stage
FROM base AS development

# Copy package files first for better layer caching
COPY package*.json ./

# Install all dependencies (including dev dependencies)
RUN npm ci --only=development

# Copy source code
COPY . .

# Change ownership to non-root user
RUN chown -R nodeuser:nodejs /usr/src/app
USER nodeuser

# Expose port
EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "run", "dev"]

# Production dependencies stage
FROM base AS deps

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM base AS production

# Copy production dependencies
COPY --from=deps --chown=nodeuser:nodejs /usr/src/app/node_modules ./node_modules

# Copy source code
COPY --chown=nodeuser:nodejs . .

# Switch to non-root user
USER nodeuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "start"] 
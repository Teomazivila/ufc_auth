# =============================================================================
# UFC Auth API - Production Dockerfile
# Following 2025 industry best practices for Node.js containerization
# =============================================================================

# Build arguments
ARG NODE_VERSION=20.11.0
ARG ALPINE_VERSION=3.19

# =============================================================================
# Stage 1: Dependencies (Base for both build and runtime)
# =============================================================================
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS dependencies

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    tini \
    && rm -rf /var/cache/apk/*

# Create app directory with proper permissions
WORKDIR /usr/src/app

# Copy package files for dependency installation
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci --include=dev --prefer-offline --no-audit --no-fund && \
    npm cache clean --force

# =============================================================================
# Stage 2: Build (Compile and prepare application)
# =============================================================================
FROM dependencies AS build

# Copy source code
COPY . .

# Run build steps (if any)
RUN npm run lint && \
    npm run test:unit && \
    npm prune --omit=dev && \
    npm cache clean --force

# Remove unnecessary files
RUN rm -rf \
    tests/ \
    docs/ \
    .github/ \
    .git/ \
    *.md \
    .eslintrc* \
    .prettierrc* \
    jest.config.* \
    nodemon.json

# =============================================================================
# Stage 3: Production Runtime
# =============================================================================
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS production

# Build metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Add metadata labels following OCI standards
LABEL org.opencontainers.image.title="UFC Auth API" \
      org.opencontainers.image.description="Identity Management API with Strong Authentication - Master's Degree Project" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="UFC Auth Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/teomaz/ufc_auth" \
      org.opencontainers.image.source="https://github.com/teomaz/ufc_auth" \
      org.opencontainers.image.documentation="https://github.com/teomaz/ufc_auth/blob/main/README.md"

# Install security updates and runtime dependencies only
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    tini \
    curl \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 1001 -S nodejs \
    && adduser -S nodejs -u 1001

# Set production environment
ENV NODE_ENV=production \
    NPM_CONFIG_LOGLEVEL=warn \
    NPM_CONFIG_PROGRESS=false \
    NODE_OPTIONS="--max-old-space-size=1024" \
    PORT=3000

# Create app directory
WORKDIR /usr/src/app

# Copy built application from build stage
COPY --from=build --chown=nodejs:nodejs /usr/src/app/node_modules ./node_modules
COPY --from=build --chown=nodejs:nodejs /usr/src/app/src ./src
COPY --from=build --chown=nodejs:nodejs /usr/src/app/package*.json ./
COPY --from=build --chown=nodejs:nodejs /usr/src/app/public ./public

# Create necessary directories with proper permissions
RUN mkdir -p logs && \
    chown -R nodejs:nodejs /usr/src/app && \
    chmod -R 755 /usr/src/app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]

# Start the application
CMD ["node", "src/server.js"] 
# Multi-stage build for security and size optimization
FROM node:18-alpine AS base

# Install security updates and required packages
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates && \
    rm -rf /var/cache/apk/*

# Create app directory with proper permissions
WORKDIR /app

# Create non-root user early
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mcp -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production --ignore-scripts && \
    npm cache clean --force

# Build stage
FROM base AS build

# Copy source code
COPY . .

# Install dev dependencies for build
RUN npm ci --ignore-scripts

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install security updates
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mcp -u 1001 -G nodejs

# Copy built application from build stage
COPY --from=build --chown=mcp:nodejs /app/build ./build
COPY --from=build --chown=mcp:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=mcp:nodejs /app/package*.json ./

# Create directories with proper permissions
RUN mkdir -p /app/logs && \
    chown -R mcp:nodejs /app && \
    chmod -R 755 /app

# Create health check script
COPY --chown=mcp:nodejs <<EOF /app/health.js
const http = require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 9093,
  path: '/health',
  method: 'GET',
  timeout: 3000
};

const req = http.request(options, (res) => {
  if (res.statusCode === 200) {
    process.exit(0);
  } else {
    process.exit(1);
  }
});

req.on('error', () => {
  process.exit(1);
});

req.on('timeout', () => {
  req.destroy();
  process.exit(1);
});

req.end();
EOF

# Switch to non-root user
USER mcp

# Expose port
EXPOSE 9093

# Environment variables
ENV NODE_ENV=production \
    PORT=9093 \
    NODE_OPTIONS="--max-old-space-size=512" \
    UV_THREADPOOL_SIZE=4

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node health.js

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "build/index.js"]

# Security labels
LABEL security.scan="true"
LABEL version="1.0.0"
LABEL description="YouTube MCP Server"
LABEL maintainer="your-email@domain.com"
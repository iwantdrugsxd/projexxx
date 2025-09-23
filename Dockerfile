# Use Node.js 18 as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy backend package files
COPY backend/package*.json ./

# Install backend dependencies only
RUN npm ci --only=production

# Copy backend source code
COPY backend/ .

# Expose port (Railway will set PORT environment variable)
EXPOSE 5001

# Set environment to production
ENV NODE_ENV=production

# Start the backend server directly
CMD ["node", "server.js"]

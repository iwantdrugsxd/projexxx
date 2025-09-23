# Use Node.js 18 as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy backend package files
COPY backend/package*.json ./

# Install backend dependencies
RUN npm ci --only=production

# Copy backend source code
COPY backend/ .

# Expose port (Railway will set PORT environment variable)
EXPOSE 5001

# Start the backend server
CMD ["npm", "start"]

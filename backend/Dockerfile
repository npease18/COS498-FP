FROM node:lts

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json first for better caching
COPY backend/package*.json ./backend/

WORKDIR /app/backend/

# Install dependencies
RUN npm install

# Create directories that will be mounted
# RUN mkdir -p /app/views /app/partials /app/public

# Expose port (internal to container network)
EXPOSE 3000

# Start the application with nodemon for auto-restart
CMD ["npm", "run", "dev"]
FROM node:lts

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

WORKDIR /app/backend/

# Install dependencies
RUN npm install

# Expose port (internal to container network)
EXPOSE 3000

# Start the application
CMD ["node", "server.js"]
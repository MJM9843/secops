# Use Node.js base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package manifest(s)
COPY package*.json ./

# Install dependencies
RUN npm install --silent

# Copy backend source code
COPY . .

# Expose port the backend listens on (adjust as per your server config)
EXPOSE 8000

# Start the backend server — adjust command if you use e.g. ts-node, or a custom script
CMD ["npm", "start"]

# Use Node.js as base — choose a stable version
FROM node:18-alpine

# Set working directory inside container
WORKDIR /app

# Copy package manifest (and lock file if exists) first
COPY package*.json ./

# Install dependencies
RUN npm install --silent

# Copy the rest of frontend source code
COPY . .

# Build the frontend (if it's a build step, e.g. React)
RUN npm run build

# Install a simple static server (optional — if you serve build output via something like serve)
RUN npm install -g serve

# Expose port (for static server)
EXPOSE 3000

# Start the static server to serve the built files
CMD ["serve", "-s", "build", "-l", "3000"]

FROM node:18

WORKDIR /app

# Copy dependencies first
COPY package*.json ./

RUN npm install

# Copy all frontend source code
COPY . .

# Build production version
RUN npm run build

# Use lightweight Nginx to serve static files
FROM nginx:alpine

COPY --from=0 /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

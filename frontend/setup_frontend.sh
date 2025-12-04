#!/bin/bash
# File: frontend/setup_frontend.sh

set -e

echo "=================================================="
echo "SecOps Frontend Setup & Deployment Script"
echo "=================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Please do not run as root${NC}"
    exit 1
fi

echo -e "${GREEN}[1/8] Updating system packages...${NC}"
sudo apt-get update -y

echo -e "${GREEN}[2/8] Installing Node.js 20.x...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

echo -e "${GREEN}[3/8] Verifying Node.js and npm installation...${NC}"
node --version
npm --version

echo -e "${GREEN}[4/8] Installing dependencies...${NC}"
npm install

echo -e "${GREEN}[5/8] Creating production build...${NC}"
npm run build

echo -e "${GREEN}[6/8] Installing serve globally...${NC}"
sudo npm install -g serve pm2

echo -e "${GREEN}[7/8] Setting up PM2 service...${NC}"
CURRENT_DIR=$(pwd)
USER=$(whoami)

# Create PM2 ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'secops-frontend',
    script: 'serve',
    args: '-s build -l 3000',
    cwd: '$CURRENT_DIR',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
EOF

echo -e "${GREEN}[8/8] Starting frontend with PM2...${NC}"
pm2 start ecosystem.config.js
pm2 save
pm2 startup | tail -n 1 | sudo bash

echo ""
echo -e "${GREEN}=================================================="
echo "Frontend Setup Complete!"
echo "=================================================="
echo -e "${NC}"
pm2 status
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Check status:  pm2 status"
echo "  Stop app:      pm2 stop secops-frontend"
echo "  Start app:     pm2 start secops-frontend"
echo "  Restart app:   pm2 restart secops-frontend"
echo "  View logs:     pm2 logs secops-frontend"
echo "  Monitor:       pm2 monit"
echo ""
echo -e "${GREEN}Frontend running at: http://localhost:3000${NC}"
echo -e "${GREEN}Backend API should be at: http://localhost:8000${NC}"
echo ""
echo -e "${YELLOW}Note: Update REACT_APP_API_URL in .env if backend is on different host${NC}"

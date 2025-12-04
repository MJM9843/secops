#!/bin/bash
# File: backend/setup_backend.sh

set -e

echo "=================================================="
echo "SecOps Backend Setup & Deployment Script"
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
sudo apt-get upgrade -y

echo -e "${GREEN}[2/8] Installing Python 3.11 and dependencies...${NC}"
sudo apt-get install -y python3.11 python3.11-venv python3-pip python3.11-dev build-essential libssl-dev libffi-dev

echo -e "${GREEN}[3/8] Creating virtual environment...${NC}"
python3.11 -m venv venv
source venv/bin/activate

echo -e "${GREEN}[4/8] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel

echo -e "${GREEN}[5/8] Installing Python packages...${NC}"
pip install fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0 \
    boto3==1.34.34 \
    botocore==1.34.34 \
    python-multipart==0.0.6 \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    python-dotenv==1.0.0 \
    httpx==0.26.0 \
    aiofiles==23.2.1

echo -e "${GREEN}[6/8] Creating .env file...${NC}"
cat > .env << EOF
# SecOps Backend Configuration
APP_NAME=SecOps
ENVIRONMENT=production
DEBUG=False
API_V1_STR=/api/v1
SECRET_KEY=$(openssl rand -hex 32)
BACKEND_CORS_ORIGINS=["http://localhost:3000","http://localhost:5000"]
LOG_LEVEL=INFO
EOF

echo -e "${GREEN}[7/8] Setting up systemd service...${NC}"
CURRENT_DIR=$(pwd)
USER=$(whoami)

sudo tee /etc/systemd/system/secops-backend.service > /dev/null << EOF
[Unit]
Description=SecOps Backend API Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$CURRENT_DIR
Environment="PATH=$CURRENT_DIR/venv/bin"
ExecStart=$CURRENT_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --log-level info
Restart=always
RestartSec=10
StandardOutput=append:/var/log/secops-backend.log
StandardError=append:/var/log/secops-backend-error.log

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}[8/8] Creating log files and setting permissions...${NC}"
sudo touch /var/log/secops-backend.log
sudo touch /var/log/secops-backend-error.log
sudo chown $USER:$USER /var/log/secops-backend.log
sudo chown $USER:$USER /var/log/secops-backend-error.log
sudo chmod 644 /var/log/secops-backend.log
sudo chmod 644 /var/log/secops-backend-error.log

echo -e "${GREEN}Starting SecOps Backend Service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable secops-backend.service
sudo systemctl start secops-backend.service

echo ""
echo -e "${GREEN}=================================================="
echo "Backend Setup Complete!"
echo "=================================================="
echo -e "Service Status: ${NC}"
sudo systemctl status secops-backend.service --no-pager
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Check status:  sudo systemctl status secops-backend"
echo "  Stop service:  sudo systemctl stop secops-backend"
echo "  Start service: sudo systemctl start secops-backend"
echo "  Restart:       sudo systemctl restart secops-backend"
echo "  View logs:     sudo tail -f /var/log/secops-backend.log"
echo "  View errors:   sudo tail -f /var/log/secops-backend-error.log"
echo ""
echo -e "${GREEN}Backend API running at: http://localhost:8000${NC}"
echo -e "${GREEN}API Documentation: http://localhost:8000/docs${NC}"

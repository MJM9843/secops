// File: frontend/ecosystem.config.js

module.exports = {
  apps: [{
    name: 'secops-frontend',
    script: './start.sh',
    cwd: '/home/ubuntu/secops/frontend',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    interpreter: '/bin/bash',
    env: {
      NODE_ENV: 'production'
    }
  }]
};

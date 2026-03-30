module.exports = {
  apps: [{
    name: 'saudi-cam',
    script: '/root/chat/chat-server-v2.js',
    env: {
      DB_PASSWORD: 'chatpass123',
      NODE_ENV: 'production'
    }
  }]
};

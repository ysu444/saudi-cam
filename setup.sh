#!/bin/bash
# =============================================================
#  Saudi Cam - سكربت التثبيت التلقائي
#  استخدام: bash setup.sh yourdomain.com
# =============================================================

set -e

DOMAIN=${1:-""}
DB_NAME="saudicam"
DB_USER="chatadmin"
DB_PASS="chatpass123"
APP_PORT=8089

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# =============================================================
#  1. تحقق من الروت
# =============================================================
if [ "$EUID" -ne 0 ]; then
  err "شغل السكربت كـ root: sudo bash setup.sh"
fi

echo ""
echo "========================================="
echo "   سعودي كام - تثبيت تلقائي"
echo "========================================="
echo ""

# =============================================================
#  2. تثبيت البرامج الأساسية
# =============================================================
log "تحديث النظام وتثبيت البرامج..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
apt-get install -y -qq nodejs postgresql postgresql-contrib redis-server nginx certbot python3-certbot-nginx > /dev/null 2>&1

log "Node.js $(node -v) | npm $(npm -v)"
log "PostgreSQL $(psql --version | grep -oP '\d+\.\d+')"
log "Redis $(redis-cli --version | grep -oP '\d+\.\d+\.\d+')"

# =============================================================
#  3. تثبيت PM2
# =============================================================
if ! command -v pm2 &> /dev/null; then
  npm install -g pm2 > /dev/null 2>&1
fi
log "PM2 $(pm2 -v)"

# =============================================================
#  4. تثبيت MediaMTX
# =============================================================
if ! command -v mediamtx &> /dev/null; then
  log "تثبيت MediaMTX..."
  cd /tmp
  wget -q https://github.com/bluenviron/mediamtx/releases/download/v1.9.3/mediamtx_v1.9.3_linux_amd64.tar.gz
  tar xzf mediamtx_v1.9.3_linux_amd64.tar.gz
  mv mediamtx /usr/local/bin/
  chmod +x /usr/local/bin/mediamtx
  rm -f mediamtx_v1.9.3_linux_amd64.tar.gz mediamtx.yml LICENSE
fi
log "MediaMTX $(mediamtx --version 2>&1 || echo 'installed')"

# =============================================================
#  5. إعداد قاعدة البيانات
# =============================================================
log "إعداد PostgreSQL..."

# إنشاء المستخدم وقاعدة البيانات
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" > /dev/null 2>&1

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" > /dev/null 2>&1

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" > /dev/null 2>&1

# إنشاء الجداول
sudo -u postgres psql -d ${DB_NAME} << 'SQLEOF'
-- Settings
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

-- Users
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, display_name TEXT, role TEXT DEFAULT 'guest',
  badge TEXT DEFAULT '', enabled BOOLEAN DEFAULT true, avatar_url TEXT DEFAULT '',
  permissions TEXT DEFAULT '[]', created_at TIMESTAMPTZ DEFAULT NOW(), last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- Rooms
CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, password TEXT DEFAULT '', icon TEXT DEFAULT '',
  marquee TEXT DEFAULT '', fixed_text TEXT DEFAULT '', bg_image TEXT DEFAULT '',
  pinned_msg TEXT DEFAULT '', max_users INTEGER DEFAULT 0, max_speakers INTEGER DEFAULT 0,
  mic_queue_mode TEXT DEFAULT 'free', mic_auto_release INTEGER DEFAULT 0,
  mic_mode TEXT DEFAULT 'all', cam_mode TEXT DEFAULT 'all', chat_mode TEXT DEFAULT 'all',
  allowed_roles TEXT DEFAULT 'all', perms TEXT DEFAULT '{}',
  is_default BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Mods
CREATE TABLE IF NOT EXISTS mods (
  id SERIAL PRIMARY KEY, display_name TEXT NOT NULL, code TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT DEFAULT 'mod', badge TEXT DEFAULT '',
  permissions TEXT DEFAULT '[]', enabled BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Bans
CREATE TABLE IF NOT EXISTS bans (
  id SERIAL PRIMARY KEY, username TEXT NOT NULL, reason TEXT DEFAULT '',
  banned_by TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY, room_id TEXT, username TEXT, text TEXT,
  msg_type TEXT DEFAULT 'chat', target TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Logs
CREATE TABLE IF NOT EXISTS logs (
  id SERIAL PRIMARY KEY, action TEXT NOT NULL, details TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Device tracking
CREATE TABLE IF NOT EXISTS device_tracks (
  id SERIAL PRIMARY KEY, fingerprint TEXT, ip TEXT, username TEXT,
  user_agent TEXT DEFAULT '', screen_size TEXT DEFAULT '', language TEXT DEFAULT '',
  platform TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Device bans
CREATE TABLE IF NOT EXISTS device_bans (
  id SERIAL PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, reason TEXT DEFAULT '',
  banned_by TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Daily stats
CREATE TABLE IF NOT EXISTS daily_stats (date DATE PRIMARY KEY, visitors INTEGER DEFAULT 0);

-- Subscription plans
CREATE TABLE IF NOT EXISTS sub_plans (
  id SERIAL PRIMARY KEY, name TEXT, name_ar TEXT, price NUMERIC DEFAULT 0,
  currency TEXT DEFAULT 'SAR', duration_days INTEGER DEFAULT 30, badge TEXT DEFAULT '',
  role TEXT DEFAULT 'vip', color TEXT DEFAULT '#ffd700', features TEXT DEFAULT '[]',
  sort_order INTEGER DEFAULT 0, enabled BOOLEAN DEFAULT true
);

-- User subscriptions
CREATE TABLE IF NOT EXISTS user_subs (
  id SERIAL PRIMARY KEY, username TEXT NOT NULL, plan_id INTEGER REFERENCES sub_plans(id),
  status TEXT DEFAULT 'active', start_date TIMESTAMPTZ DEFAULT NOW(),
  end_date TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Room rentals
CREATE TABLE IF NOT EXISTS room_rentals (
  id SERIAL PRIMARY KEY, username TEXT, room_name TEXT, price NUMERIC DEFAULT 0,
  currency TEXT DEFAULT 'SAR', start_date TIMESTAMPTZ DEFAULT NOW(),
  end_date TIMESTAMPTZ, notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Invite codes
CREATE TABLE IF NOT EXISTS invite_codes (
  code TEXT PRIMARY KEY, created_by TEXT DEFAULT 'admin', role TEXT DEFAULT 'member',
  max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Roles
CREATE TABLE IF NOT EXISTS roles (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, name_ar TEXT DEFAULT '',
  color TEXT DEFAULT '#ffffff', icon TEXT DEFAULT '', priority INTEGER DEFAULT 0,
  is_system BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default room
INSERT INTO rooms (id, name, is_default) VALUES ('general', 'الغرفة العامة', true) ON CONFLICT (id) DO NOTHING;

-- Default roles
INSERT INTO roles (name, name_ar, color, icon, priority, is_system) VALUES
  ('owner', 'مالك', '#ff0000', '', 100, true),
  ('admin', 'مدير', '#ff4444', '', 90, true),
  ('mod', 'مشرف', '#44aaff', '', 50, true),
  ('vip', 'VIP', '#ffd700', '', 30, false),
  ('member', 'عضو', '#44ff44', '', 20, false),
  ('guest', 'زائر', '#888888', '', 0, true)
ON CONFLICT DO NOTHING;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(username);
CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at);
CREATE INDEX IF NOT EXISTS idx_bans_username ON bans(username);
CREATE INDEX IF NOT EXISTS idx_device_tracks_fp ON device_tracks(fingerprint);
CREATE INDEX IF NOT EXISTS idx_device_tracks_user ON device_tracks(username);

-- Permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO chatadmin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO chatadmin;
SQLEOF

log "قاعدة البيانات جاهزة"

# =============================================================
#  6. تثبيت مكتبات Node.js
# =============================================================
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
log "تثبيت المكتبات في ${APP_DIR}..."
cd "${APP_DIR}"
npm install --production > /dev/null 2>&1
log "npm packages installed"

# =============================================================
#  7. إعداد MediaMTX config
# =============================================================
SERVER_IP=$(curl -s ifconfig.me)
cat > "${APP_DIR}/mediamtx.yml" << MTXEOF
logLevel: info
logDestinations: [stdout]
api: yes
apiAddress: 127.0.0.1:9997
rtsp: no
rtmp: no
srt: no
webrtc: yes
webrtcAddress: :8889
webrtcAdditionalHosts:
  - ${SERVER_IP}
webrtcICEServers2:
  - url: stun:stun.l.google.com:19302
hls: yes
hlsAddress: :8888
hlsAllowOrigin: "*"
hlsAlwaysRemux: yes
hlsSegmentCount: 3
hlsSegmentDuration: 1s
paths:
  all_others:
MTXEOF
log "MediaMTX config ready"

# =============================================================
#  8. إعداد MediaMTX service
# =============================================================
cat > /etc/systemd/system/mediamtx.service << SVCEOF
[Unit]
Description=MediaMTX
After=network.target

[Service]
ExecStart=/usr/local/bin/mediamtx ${APP_DIR}/mediamtx.yml
Restart=always
RestartSec=3
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable mediamtx > /dev/null 2>&1
systemctl restart mediamtx
log "MediaMTX running"

# =============================================================
#  9. إعداد PM2
# =============================================================
pm2 delete saudi-cam 2>/dev/null || true
cd "${APP_DIR}"
DB_PASSWORD=${DB_PASS} pm2 start ecosystem.config.js
pm2 save > /dev/null 2>&1
pm2 startup systemd -u root --hp /root > /dev/null 2>&1 || true
log "Chat server running on port ${APP_PORT}"

# =============================================================
#  10. Firewall
# =============================================================
ufw allow 22/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw allow 8189/udp > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1
log "Firewall configured"

# =============================================================
#  11. Nginx
# =============================================================
if [ -n "$DOMAIN" ]; then
  SERVER_NAME="${DOMAIN} www.${DOMAIN}"
else
  SERVER_NAME="_"
  DOMAIN="$(curl -s ifconfig.me)"
fi

cat > /etc/nginx/sites-available/ksacam << NGEOF
server {
    listen 80;
    server_name ${SERVER_NAME};

    location ~ ^/hls/(.+)/(whip|whep)\$ {
        proxy_pass http://127.0.0.1:8889/\$1/\$2;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        add_header Access-Control-Allow-Origin * always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS, PATCH" always;
        add_header Access-Control-Allow-Headers "Content-Type" always;
    }

    location /hls/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 86400;
        add_header Access-Control-Allow-Origin * always;
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
NGEOF

ln -sf /etc/nginx/sites-available/ksacam /etc/nginx/sites-enabled/ksacam
rm -f /etc/nginx/sites-enabled/default
nginx -t > /dev/null 2>&1 && systemctl restart nginx
log "Nginx configured"

# =============================================================
#  12. SSL (إذا فيه دومين)
# =============================================================
if [ "$SERVER_NAME" != "_" ]; then
  log "تركيب شهادة SSL لـ ${DOMAIN}..."
  certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --email admin@${DOMAIN} > /dev/null 2>&1 && \
    log "SSL installed for ${DOMAIN}" || \
    warn "SSL failed - تأكد إن DNS يشير للسيرفر"
fi

# =============================================================
#  Done!
# =============================================================
echo ""
echo "========================================="
echo -e "${GREEN}   التثبيت تم بنجاح!${NC}"
echo "========================================="
echo ""
if [ "$SERVER_NAME" != "_" ]; then
  echo "  الموقع:  https://${DOMAIN}"
  echo "  الأدمن:  https://${DOMAIN}/admin"
else
  echo "  الموقع:  http://${DOMAIN}"
  echo "  الأدمن:  http://${DOMAIN}/admin"
fi
echo "  كلمة سر الأدمن: admin123"
echo ""
echo "========================================="

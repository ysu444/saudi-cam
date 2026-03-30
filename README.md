# شات البحرين - دردشة كتابية صوتية كام لايف
### bh.chat | bema.chat

> منصة دردشة عربية احترافية متكاملة - كتابي + صوتي + كام لايف

---

## 🏗️ البنية التقنية

```
┌─────────────────────────────────────────────────────┐
│                    الإنترنت                          │
│                       ↓                              │
│              nginx (HTTPS/SSL)                       │
│                 :443 / :80                           │
│                       ↓                              │
│    ┌──────────────────┼──────────────────┐           │
│    ↓                  ↓                  ↓           │
│  Node.js           MediaMTX          PostgreSQL      │
│  :8089             :8889               :5432         │
│  (الشات)          (الصوت/الكام)       (البيانات)     │
│    ↓                                                 │
│  Socket.IO ←→ Redis :6379                            │
│  (الاتصال الفوري)   (الجلسات + الكاش)               │
└─────────────────────────────────────────────────────┘
```

---

## 🔧 الأدوات المستخدمة

| الأداة | النسخة | الوظيفة |
|--------|--------|---------|
| **Node.js** | v20+ | السيرفر الرئيسي |
| **Socket.IO** | v4.8 | الاتصال الفوري (real-time) |
| **PostgreSQL** | v16 | قاعدة البيانات |
| **Redis** | v7 | الجلسات + الكاش |
| **nginx** | v1.24 | HTTPS + Reverse Proxy |
| **MediaMTX** | latest | بث الصوت/الكام (WebRTC WHIP/WHEP) |
| **Let's Encrypt** | - | شهادة SSL مجانية |
| **bcryptjs** | v3 | تشفير كلمات السر |
| **PM2** | latest | إدارة العمليات |

---

## 📊 السعة والأداء

| المقياس | القيمة |
|---------|--------|
| مستخدمين متزامنين | **500-1000** (2 أنوية / 4GB RAM) |
| رسائل بالثانية | **2000-5000** |
| غرف متزامنة | **غير محدود** |
| متحدثين بالمايك | **10 لكل غرفة** |
| وقت الاستجابة | **< 50ms** |

> للتوسع لـ 5000+ مستخدم: ترقية لـ 4 أنوية + 8GB RAM

---

## 📱 الميزات

### للزائر:
- 💬 دردشة كتابية فورية
- 🎤 مايك (WebRTC)
- 📷 كاميرا
- ✋ رفع يد
- 📥 فاصل (للمنشن والخاص)
- 🔒 رسائل خاصة

### للمشرف (25 صلاحية):
| الصلاحية | الوصف |
|----------|-------|
| `canKick` | طرد مستخدم |
| `canBan` | حظر اسم |
| `canDeviceBan` | حظر جهاز |
| `canMute` | كتم |
| `canWarn` | تحذير (يتحفظ + يظهر للشخص فقط) |
| `canRename` | تغيير اسم مستخدم |
| `canBadge` | تغيير شارة |
| `canPromote` | ترقية لعضو/VIP |
| `canMicOff` | قفل مايك شخص |
| `canMicBlock` | منع مايك نهائي |
| `canMicAll` | قفل/فتح مايك الكل |
| `canAllowMic` | سماح مايك |
| `canCamOff` | قفل كام شخص |
| `canCamBlock` | منع كام نهائي |
| `canAllowCam` | سماح كام |
| `canChatBlock` | منع كتابة |
| `canChatLock` | قفل كتابة الغرفة |
| `canRenameRoom` | تسمية الغرفة |
| `canEditMarquee` | الرسالة المتحركة |
| `canManageRooms` | إدارة الغرف |
| `canMuteAll` | كتم الكل |
| `canPinMsg` | تثبيت رسالة |
| `canClearChat` | مسح رسائل الغرفة |
| `canAnnounce` | إعلان للغرفة |
| `canViewIP` | معلومات الجهاز |

### لوحة التحكم (14 قسم):
1. 🖥️ حالة السيرفر
2. 📊 نظرة عامة
3. 👥 المستخدمين
4. 🏠 الغرف
5. 🚫 فلتر الكلمات
6. 🛡️ المشرفين
7. 🎨 المظهر والثيمات
8. 📋 السجلات
9. ⚙️ الإعدادات
10. 💾 إدارة البيانات
11. 🎤 إدارة المايك
12. 📢 الإعلانات
13. 🚫 المحظورين
14. 🎟️ أكواد الدعوة

---

## 🔐 الحماية

| الطبقة | التقنية |
|--------|---------|
| التشفير | HTTPS (TLS 1.2/1.3) |
| كلمات السر | bcrypt (10 rounds) |
| الجلسات | Redis + TTL |
| Rate Limiting | 10/دقيقة (login)، 5/5دقائق (admin) |
| CORS | مقيّد للدومين فقط |
| Security Headers | X-Frame-Options, XSS-Protection, nosniff |
| Body Limit | 512 KB |
| API Protection | 86/86 endpoint محمي (100%) |

---

## 🗄️ قاعدة البيانات

| الجدول | الوظيفة |
|--------|---------|
| `users` | المستخدمين |
| `rooms` | الغرف |
| `messages` | الرسائل |
| `mods` | المشرفين |
| `bans` | المحظورين |
| `warnings` | التحذيرات |
| `logs` | السجلات |
| `device_tracks` | بصمات الأجهزة |
| `device_bans` | حظر أجهزة |
| `settings` | الإعدادات |
| `invite_codes` | أكواد الدعوة |
| `daily_stats` | إحصائيات يومية |

---

## 🚀 التنصيب

### المتطلبات:
- Ubuntu 22.04+ أو أي Linux
- Node.js 18+
- PostgreSQL 14+
- Redis 6+
- nginx
- دومين + SSL

### الخطوات:

```bash
# 1. تجهيز السيرفر
apt update && apt upgrade -y
apt install -y nodejs npm nginx redis-server postgresql

# 2. إعداد قاعدة البيانات
sudo -u postgres psql -c "CREATE USER chatadmin WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE signalchat OWNER chatadmin;"

# 3. استنساخ المشروع
cd /root
git clone https://github.com/ihub2/web-chat.git chat
cd chat
npm install

# 4. إعداد الجداول
node db.js

# 5. إعداد المتغيرات
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'signal-chat',
    script: 'chat-server-v2.js',
    env: {
      DB_PASSWORD: 'YOUR_DB_PASSWORD',
      NODE_ENV: 'production'
    }
  }]
};
EOF

# 6. تشغيل
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup

# 7. إعداد nginx
cat > /etc/nginx/sites-enabled/chat << 'EOF'
server {
    server_name YOUR_DOMAIN;
    server_tokens off;

    location = /data.json { return 403; }
    location = /package.json { return 403; }
    location = /db.js { return 403; }
    location = /chat-server-v2.js { return 403; }

    location / {
        proxy_pass http://127.0.0.1:8089;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /hls/ {
        proxy_pass http://127.0.0.1:8889/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    listen 80;
}
EOF
nginx -t && nginx -s reload

# 8. SSL
apt install -y certbot python3-certbot-nginx
certbot --nginx -d YOUR_DOMAIN

# 9. جدار الحماية
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# 10. MediaMTX (للمايك والكام)
mkdir -p /root/mediamtx && cd /root/mediamtx
wget https://github.com/bluenviron/mediamtx/releases/latest/download/mediamtx_v1.9.1_linux_amd64.tar.gz
tar xzf mediamtx_*.tar.gz
pm2 start ./mediamtx --name mediamtx
```

### بعد التنصيب:
1. افتح `https://YOUR_DOMAIN/admin`
2. كلمة السر الافتراضية: `admin123`
3. **غيّر كلمة السر فوراً** من الإعدادات

---

## 📁 هيكل الملفات

```
/root/chat/
├── chat-server-v2.js      # السيرفر (APIs + Socket.IO)
├── web-chat.html           # واجهة الشات
├── admin.html              # لوحة التحكم
├── db.js                   # إعداد قاعدة البيانات
├── package.json            # التبعيات
├── ecosystem.config.js     # إعدادات PM2
├── manifest.json           # PWA
├── sw.js                   # Service Worker
├── robots.txt              # SEO
└── sitemap.xml             # SEO
```

---

## 📄 الرخصة

هذا المشروع ملكية خاصة لـ **bema.chat**

---

*تم التطوير بمساعدة Claude AI*

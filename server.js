const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client');
const path = require('path');
require('dotenv').config();

const app = express();
const port = 3000;
const SECRET_KEY = 'trend-super-secret-key-123!';

// --- الحد الأقصى للأجهزة المسموح بها لكل حساب ---
const MAX_DEVICES = 2;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- إعداد قاعدة بيانات Turso ---
const URL = process.env.TURSO_URL || 'libsql://trenddb-sdfg6.aws-ap-south-1.turso.io';
const TOKEN = process.env.TURSO_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODI3OTg2NTIsImlkIjoiMDE5ZjE3MTEtMjUwMS03NWVmLWE1MTUtYjc4ODUzOWFhMDhjIiwia2lkIjoiQ3AzMnRsemJUQzZFaENfZmx1VzdzMGw1ZFNlMVVsdmROV0xzVVgwSzFnRSIsInJpZCI6IjcyNDU5ZWY5LWFlNzYtNDk0ZC1iMGU1LTVkMjg5ZDQ5NWQ2NyJ9.JIzsbHw35VVexaXwkBCC9v6eJ1AFlBjCH99aMr367UppfzQgmR5jrNBwCl79_-x-lTnotQq5QgwYMdk5I3ovBA';

const turso = createClient({ url: URL, authToken: TOKEN });

// محول (Wrapper) لكي تعمل الأكواد القديمة مع Turso بدون تعديل
const db = {
    serialize: (cb) => { cb(); },
    run: (query, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        turso.execute({ sql: query, args: params }).then(res => {
            if (cb) cb.call({ lastID: Number(res.lastInsertRowid) }, null);
        }).catch(err => { if (cb) cb(err); });
    },
    get: (query, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        turso.execute({ sql: query, args: params }).then(res => {
            if (cb) cb(null, res.rows.length > 0 ? res.rows[0] : null);
        }).catch(err => { if (cb) cb(err); });
    },
    all: (query, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        turso.execute({ sql: query, args: params }).then(res => {
            if (cb) cb(null, res.rows);
        }).catch(err => { if (cb) cb(err); });
    }
};

// ============================================================
// إنشاء الجداول الجديدة عند بدء التشغيل
// ============================================================
db.serialize(() => {
    // جدول أجهزة المستخدمين (بصمات الأجهزة)
    db.run(`CREATE TABLE IF NOT EXISTS user_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_fingerprint TEXT,
        browser TEXT,
        os TEXT,
        screen_resolution TEXT,
        timezone TEXT,
        ip TEXT,
        country TEXT,
        city TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // سجل عمليات الدخول الكامل
    db.run(`CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT,
        device_fingerprint TEXT,
        browser TEXT,
        os TEXT,
        screen_resolution TEXT,
        timezone TEXT,
        ip TEXT,
        country TEXT,
        city TEXT,
        flagged INTEGER DEFAULT 0,
        flag_reason TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // سجل أحداث تبديل التبويب (مؤشر احتمالي فقط)
    db.run(`CREATE TABLE IF NOT EXISTS visibility_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        event_type TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // إضافة عمود suspended لجدول users إن لم يكن موجوداً
    db.run("ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0", (err) => {
        // تجاهل الخطأ إذا كان العمود موجوداً مسبقاً
    });
});

// ============================================================
// Middleware: التحقق من التوكن
// ============================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'غير مصرح لك بالدخول (فقط للآدمن)' });
    }
}

// ============================================================
// دالة مساعدة: جلب الموقع الجغرافي من IP
// ============================================================
async function getGeoFromIP(ip) {
    try {
        // تنظيف IP المحلي
        const cleanIP = (ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') ? '' : ip;
        if (!cleanIP) return { country: 'محلي', city: 'localhost' };

        const res = await fetch(`http://ip-api.com/json/${cleanIP}?fields=country,city&lang=ar`);
        const data = await res.json();
        return { country: data.country || 'غير معروف', city: data.city || 'غير معروف' };
    } catch (e) {
        return { country: 'غير معروف', city: 'غير معروف' };
    }
}

// ============================================================
// دالة مساعدة: فحص مشاركة الحساب (التنبيهات)
// ============================================================
function checkSharingFlags(userId, deviceFingerprint, country, callback) {
    const flags = [];
    const now24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    // فحص 1: أكثر من بصمة جهاز خلال 24 ساعة
    db.all(
        `SELECT DISTINCT device_fingerprint FROM login_logs 
         WHERE user_id = ? AND timestamp > ? AND device_fingerprint != ?`,
        [userId, now24h, deviceFingerprint],
        (err, rows) => {
            if (rows && rows.length > 0) {
                flags.push(`أجهزة متعددة خلال 24 ساعة (${rows.length + 1} أجهزة)`);
            }

            // فحص 2: دول مختلفة في نفس اليوم
            db.all(
                `SELECT DISTINCT country FROM login_logs 
                 WHERE user_id = ? AND timestamp > ? AND country != ? AND country != 'محلي'`,
                [userId, now24h, country],
                (err2, countryRows) => {
                    if (countryRows && countryRows.length > 0 && country !== 'محلي') {
                        flags.push(`دخول من دول مختلفة: ${countryRows.map(r => r.country).join(', ')} + ${country}`);
                    }
                    callback(flags);
                }
            );
        }
    );
}

// ============================================================
//  USER APIs
// ============================================================

// --- تسجيل الدخول مع تتبع الأجهزة ---
app.post('/api/login', async (req, res) => {
    const { username, password, fingerprint, browser, os, screenResolution, timezone } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'الرجاء إدخال الاسم وكلمة المرور' });

    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], async (err, row) => {
        if (err) return res.status(500).json({ error: 'خطأ في قاعدة البيانات' });
        if (!row) return res.status(401).json({ error: 'الاسم أو كلمة السر غير صحيحة' });

        // فحص الحساب المعلّق
        if (row.suspended) {
            return res.status(403).json({ error: 'تم تعليق حسابك. تواصل مع الإدارة.' });
        }

        // جلب IP والموقع الجغرافي
        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
        const geo = await getGeoFromIP(clientIP);
        const deviceFP = fingerprint || 'unknown';
        const browserInfo = browser || req.headers['user-agent'] || 'unknown';
        const osInfo = os || 'unknown';
        const screenRes = screenResolution || 'unknown';
        const tz = timezone || 'unknown';

        // فحص عدد الأجهزة النشطة (خلال آخر 30 يوم)
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        db.all(
            `SELECT DISTINCT device_fingerprint FROM user_devices 
             WHERE user_id = ? AND last_seen > ? AND device_fingerprint != ?`,
            [row.id, thirtyDaysAgo, deviceFP],
            (err2, existingDevices) => {
                const activeDeviceCount = existingDevices ? existingDevices.length : 0;
                let sessionWarning = null;

                // إذا تجاوز الحد (جهازين)، نبلّغ لكن نسمح بالدخول + تنبيه الآدمن
                if (activeDeviceCount >= MAX_DEVICES && row.username !== 'monther') {
                    sessionWarning = `تم رصد دخولك من ${activeDeviceCount + 1} أجهزة مختلفة. يتم تسجيل جميع الأجهزة ومراقبتها.`;
                }

                // فحص تنبيهات المشاركة
                checkSharingFlags(row.id, deviceFP, geo.country, (flags) => {
                    const isFlagged = flags.length > 0 ? 1 : 0;
                    const flagReason = flags.join(' | ');

                    // تسجيل في سجل الدخول الكامل
                    db.run(
                        `INSERT INTO login_logs (user_id, username, device_fingerprint, browser, os, screen_resolution, timezone, ip, country, city, flagged, flag_reason)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [row.id, row.username, deviceFP, browserInfo, osInfo, screenRes, tz, clientIP, geo.country, geo.city, isFlagged, flagReason]
                    );

                    // تحديث أو إضافة بصمة الجهاز
                    db.get(
                        "SELECT id FROM user_devices WHERE user_id = ? AND device_fingerprint = ?",
                        [row.id, deviceFP],
                        (err3, existingDevice) => {
                            if (existingDevice) {
                                db.run(
                                    `UPDATE user_devices SET last_seen = CURRENT_TIMESTAMP, ip = ?, country = ?, city = ?, browser = ?, os = ?, screen_resolution = ?, timezone = ?
                                     WHERE id = ?`,
                                    [clientIP, geo.country, geo.city, browserInfo, osInfo, screenRes, tz, existingDevice.id]
                                );
                            } else {
                                db.run(
                                    `INSERT INTO user_devices (user_id, device_fingerprint, browser, os, screen_resolution, timezone, ip, country, city)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                                    [row.id, deviceFP, browserInfo, osInfo, screenRes, tz, clientIP, geo.country, geo.city]
                                );
                            }
                        }
                    );

                    // تحديث last_login
                    db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [row.id]);

                    // إنشاء التوكن
                    const role = row.username === 'monther' ? 'admin' : 'user';
                    const token = jwt.sign({ id: row.id, username: row.username, role }, SECRET_KEY, { expiresIn: '24h' });

                    const response = { token, username: row.username, isAdmin: role === 'admin' };
                    if (sessionWarning) response.sessionWarning = sessionWarning;

                    res.json(response);
                });
            }
        );
    });
});

// --- جلب الكروت ---
app.get('/api/content', authenticateToken, (req, res) => {
    // فحص الحساب المعلّق
    db.get("SELECT suspended FROM users WHERE id = ?", [req.user.id], (err, row) => {
        if (row && row.suspended) return res.status(403).json({ error: 'تم تعليق حسابك' });

        db.all("SELECT * FROM cards ORDER BY CAST(num AS INTEGER) ASC", [], (err, rows) => {
            if (err) return res.status(500).json({ error: 'خطأ في جلب الأفكار' });
            const cards = rows.map(r => {
                try { r.links = JSON.parse(r.links); } catch(e) { r.links = []; }
                return r;
            });
            res.json(cards);
        });
    });
});

// --- تسجيل كلمات البحث ---
app.post('/api/log-search', authenticateToken, (req, res) => {
    const { keyword } = req.body;
    if (keyword && keyword.trim() !== '') {
        db.run("INSERT INTO search_logs (username, keyword) VALUES (?, ?)", [req.user.username, keyword.trim()]);
    }
    res.json({ success: true });
});

// --- تسجيل أحداث تبديل التبويب (Page Visibility) ---
app.post('/api/log-visibility', authenticateToken, (req, res) => {
    const { eventType } = req.body;
    if (eventType) {
        db.run(
            "INSERT INTO visibility_logs (user_id, username, event_type) VALUES (?, ?, ?)",
            [req.user.id, req.user.username, eventType]
        );
    }
    res.json({ success: true });
});

// ============================================================
//  ADMIN APIs
// ============================================================

// --- الإحصائيات العامة ---
app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
    const stats = {};
    db.get("SELECT count(*) as total_users FROM users", (err, row) => {
        stats.totalUsers = row ? row.total_users : 0;
        db.all("SELECT username, last_login FROM users ORDER BY last_login DESC LIMIT 5", (err, rows) => {
            stats.recentLogins = rows || [];
            db.all("SELECT keyword, count(*) as count FROM search_logs GROUP BY keyword ORDER BY count DESC LIMIT 10", (err, rows) => {
                stats.topSearches = rows || [];
                res.json(stats);
            });
        });
    });
});

// --- إحصائيات الأمان والمراقبة مع درجة المخاطرة ---
app.get('/api/admin/security', authenticateToken, requireAdmin, (req, res) => {
    const days = parseInt(req.query.days) || 7;
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    const security = {};

    // عدد التنبيهات
    db.get("SELECT count(*) as count FROM login_logs WHERE flagged = 1 AND timestamp > ?", [since], (err, row) => {
        security.totalAlerts = row ? row.count : 0;

        // جميع المستخدمين مع بيانات الأجهزة والـ IPs ودرجة المخاطرة
        db.all(
            `SELECT u.id, u.username, u.suspended,
                    count(DISTINCT d.device_fingerprint) as device_count,
                    count(DISTINCT d.ip) as ip_count,
                    count(DISTINCT d.country) as country_count,
                    group_concat(DISTINCT d.country) as countries,
                    group_concat(DISTINCT d.ip) as ips
             FROM users u
             LEFT JOIN user_devices d ON u.id = d.user_id AND d.last_seen > ?
             WHERE u.username != 'monther'
             GROUP BY u.id
             ORDER BY device_count DESC`,
            [since],
            (err, allUsers) => {
                // حساب درجة المخاطرة لكل مستخدم
                // Risk Score = (عدد الأجهزة × 20) + (عدد IPs × 10) + (عدد الدول × 30)
                // الحد الأقصى 100، الحد الأدنى 0
                const usersWithRisk = (allUsers || []).map(u => {
                    let score = 0;
                    score += Math.min((u.device_count - 1) * 20, 40);  // 0-40 نقطة
                    score += Math.min((u.ip_count - 1) * 10, 30);      // 0-30 نقطة
                    score += Math.min((u.country_count - 1) * 30, 30); // 0-30 نقطة
                    score = Math.max(0, Math.min(100, score));
                    u.risk_score = score;
                    return u;
                });

                // الحسابات المشبوهة فقط (أكثر من جهاز أو أكثر من IP)
                security.suspiciousUsers = usersWithRisk.filter(u => u.device_count > 1 || u.ip_count > 1);
                security.suspiciousUsers.sort((a, b) => b.risk_score - a.risk_score);

                // جميع المستخدمين مع درجة المخاطرة (للجدول الكامل)
                security.allUsersRisk = usersWithRisk;

                // عدد التنبيهات لكل مستخدم
                db.all(
                    `SELECT username, count(*) as alert_count FROM login_logs
                     WHERE flagged = 1 AND timestamp > ? GROUP BY username`,
                    [since],
                    (err, alertRows) => {
                        const alertMap = {};
                        (alertRows || []).forEach(r => alertMap[r.username] = r.alert_count);
                        security.suspiciousUsers.forEach(u => {
                            u.alert_count = alertMap[u.username] || 0;
                            // تعديل درجة المخاطرة بناءً على التنبيهات
                            u.risk_score = Math.min(100, u.risk_score + Math.min(u.alert_count * 5, 20));
                        });
                        security.allUsersRisk.forEach(u => {
                            u.alert_count = alertMap[u.username] || 0;
                        });

                        // إجمالي الأجهزة المسجلة
                        db.get("SELECT count(DISTINCT device_fingerprint) as count FROM user_devices WHERE last_seen > ?", [since], (err, row) => {
                            security.totalDevices = row ? row.count : 0;

                            // إجمالي IPs الفريدة
                            db.get("SELECT count(DISTINCT ip) as count FROM user_devices WHERE last_seen > ?", [since], (err, row) => {
                                security.totalUniqueIPs = row ? row.count : 0;

                                // عدد الحسابات المعلقة
                                db.get("SELECT count(*) as count FROM users WHERE suspended = 1", (err, row) => {
                                    security.suspendedCount = row ? row.count : 0;

                                    // أحداث تبديل التبويب المتكررة
                                    db.all(
                                        `SELECT username, count(*) as count FROM visibility_logs 
                                         WHERE timestamp > ? GROUP BY username HAVING count > 10 ORDER BY count DESC LIMIT 10`,
                                        [since],
                                        (err, visRows) => {
                                            security.frequentTabSwitchers = visRows || [];
                                            res.json(security);
                                        }
                                    );
                                });
                            });
                        });
                    }
                );
            }
        );
    });
});

// --- سجل الدخول الكامل ---
app.get('/api/admin/login-logs', authenticateToken, requireAdmin, (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const username = req.query.username || null;

    let query = "SELECT * FROM login_logs";
    let params = [];

    if (username) {
        query += " WHERE username = ?";
        params.push(username);
    }
    query += " ORDER BY timestamp DESC LIMIT ?";
    params.push(limit);

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'خطأ' });
        res.json(rows || []);
    });
});

// --- أجهزة مستخدم معيّن ---
app.get('/api/admin/user-devices/:id', authenticateToken, requireAdmin, (req, res) => {
    db.all(
        "SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen DESC",
        [req.params.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'خطأ' });
            res.json(rows || []);
        }
    );
});

// --- تعليق حساب ---
app.post('/api/admin/suspend/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run("UPDATE users SET suspended = 1 WHERE id = ?", [req.params.id], function(err) {
        res.json({ success: !err });
    });
});

// --- إلغاء تعليق حساب ---
app.post('/api/admin/unsuspend/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run("UPDATE users SET suspended = 0 WHERE id = ?", [req.params.id], function(err) {
        res.json({ success: !err });
    });
});

// --- إدارة المستخدمين ---
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    db.all("SELECT id, username, last_login, suspended FROM users WHERE username != 'monther'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'خطأ في جلب المستخدمين' });
        res.json(rows);
    });
});
app.post('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const { username, password } = req.body;
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password], function(err) {
        if (err) return res.status(400).json({ error: 'هذا الاسم موجود مسبقاً' });
        res.json({ success: true });
    });
});
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
        res.json({ success: !err });
    });
});

// --- إدارة الكروت ---
app.post('/api/admin/cards', authenticateToken, requireAdmin, (req, res) => {
    const { num, badge, tag, text, links } = req.body;
    const linksJson = JSON.stringify(links || []);
    db.run("INSERT INTO cards (num, badge, tag, text, links) VALUES (?, ?, ?, ?, ?)", [num, badge, tag, text, linksJson], function(err) {
        if (err) return res.status(500).json({ error: 'خطأ في الحفظ' });
        res.json({ success: true, id: this.lastID });
    });
});
app.put('/api/admin/cards/:id', authenticateToken, requireAdmin, (req, res) => {
    const { num, badge, tag, text, links } = req.body;
    const linksJson = JSON.stringify(links || []);
    db.run("UPDATE cards SET num=?, badge=?, tag=?, text=?, links=? WHERE id=?", [num, badge, tag, text, linksJson, req.params.id], function(err) {
        res.json({ success: !err });
    });
});
app.delete('/api/admin/cards/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run("DELETE FROM cards WHERE id = ?", [req.params.id], function(err) {
        res.json({ success: !err });
    });
});

// ============================================================
//  تصدير التطبيق وتشغيله
// ============================================================
if (require.main === module) {
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}
module.exports = app;

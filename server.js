const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const app = express();
const port = 3000;
const JWT_SECRET = 'gizli-anahtar-123'; // Gerçek uygulamada bu değer güvenli bir şekilde saklanmalı

// CSRF koruması için middleware
const csrfProtection = csrf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] });
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser('gizli-bir-secret'));
app.use(fileUpload({
    createParentPath: true,
    limits: { 
        fileSize: 50 * 1024 * 1024 // 50MB max file size
    }
}));
app.use(express.static('public'));
app.use(csrfProtection);

// WebSocket sunucusu oluştur
const wss = new WebSocket.Server({ port: 3001 });

// Online kullanıcıları takip etmek için
let onlineUsers = new Set();

wss.on('connection', (ws) => {
    // Yeni kullanıcı bağlandığında
    onlineUsers.add(ws);
    
    // Tüm bağlı istemcilere güncel online kullanıcı sayısını gönder
    broadcastOnlineUsers();
    
    ws.on('close', () => {
        // Kullanıcı bağlantısı kesildiğinde
        onlineUsers.delete(ws);
        broadcastOnlineUsers();
    });
});

// Tüm bağlı istemcilere online kullanıcı sayısını gönder
function broadcastOnlineUsers() {
    const count = onlineUsers.size;
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: 'onlineUsers',
                count: count
            }));
        }
    });
}

// CSRF token endpoint'i
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Uploads klasörünü statik olarak sun
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Uploads klasörünü oluştur
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Veritabanı bağlantısı
const db = new sqlite3.Database('campus.db', (err) => {
    if (err) {
        console.error('Veritabanı bağlantı hatası:', err);
    } else {
        console.log('Veritabanına bağlandı');
        
        // Haberler tablosunu oluştur
        db.run(`
            CREATE TABLE IF NOT EXISTS news (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                image TEXT,
                publish_date TEXT NOT NULL,
                status INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Duyurular tablosunu oluştur
        db.run(`
            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                publish_date TEXT NOT NULL,
                status INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Galeri tablosunu oluştur
        db.run(`
            CREATE TABLE IF NOT EXISTS gallery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                image TEXT NOT NULL,
                category TEXT NOT NULL,
                status INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) {
                console.error('Galeri tablosu oluşturulurken hata:', err);
                return;
            }
        });

        // Ziyaretçi sayacı tablosunu oluştur
        db.run(`
            CREATE TABLE IF NOT EXISTS visitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                count INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) {
                console.error('Ziyaretçi sayacı tablosu oluşturulurken hata:', err);
                return;
            }
            // İlk kaydı oluştur
            db.run(`INSERT OR IGNORE INTO visitors (count) VALUES (0)`);
        });

        // Kullanıcılar tablosunu oluştur
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                status INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, async (err) => {
            if (err) {
                console.error('Kullanıcılar tablosu oluşturulurken hata:', err);
            } else {
                // Örnek admin kullanıcısı oluştur
                db.get('SELECT * FROM users WHERE username = ?', ['admin'], async (err, row) => {
                    if (err) {
                        console.error('Admin kullanıcısı kontrol edilirken hata:', err);
                    } else if (!row) {
                        try {
                            // Şifreyi hash'le
                            const hashedPassword = await bcrypt.hash('admin123', 10);
                            
                            db.run(`
                                INSERT INTO users (username, password, email, full_name, role, status)
                                VALUES (?, ?, ?, ?, ?, ?)
                            `, ['admin', hashedPassword, 'admin@example.com', 'Admin User', 'admin', 1], (err) => {
                                if (err) {
                                    console.error('Admin kullanıcısı oluşturulurken hata:', err);
                                } else {
                                    console.log('Örnek admin kullanıcısı oluşturuldu');
                                }
                            });
                        } catch (error) {
                            console.error('Şifre hash\'leme hatası:', error);
                        }
                    }
                });
            }
        });
    }
});

// JWT doğrulama middleware'i
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Yetkilendirme başarısız: Token bulunamadı' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Yetkilendirme başarısız: Geçersiz token' });
        }
        req.user = user;
        next();
    });
};

// Admin yetkisi kontrolü
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Bu işlem için admin yetkisi gereklidir' });
    }
    next();
};

// Editör veya Admin yetkisi kontrolü
const requireEditorOrAdmin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'editor') {
        return res.status(403).json({ error: 'Bu işlem için editör veya admin yetkisi gereklidir' });
    }
    next();
};

// Login endpoint'i
app.post('/api/login', async (req, res) => {
    console.log('Login isteği alındı');
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            console.log('Eksik kullanıcı adı veya şifre');
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gereklidir' });
        }
        const query = 'SELECT * FROM users WHERE username = ?';
        db.get(query, [username], async (err, user) => {
            if (err) {
                console.error('Login hatası:', err);
                return res.status(500).json({ error: 'Sunucu hatası' });
            }
            if (!user) {
                console.log('Kullanıcı bulunamadı');
                return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
            }
            // Şifre kontrolü
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                console.log('Geçersiz şifre');
                return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
            }
            // JWT token oluştur
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username,
                    role: user.role 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            // CSRF token oluştur
            let csrfToken = null;
            try {
                csrfToken = req.csrfToken();
                console.log('CSRF token başarıyla oluşturuldu');
            } catch (e) {
                console.error('CSRF token oluşturulamadı:', e);
            }
            res.json({
                token,
                csrfToken,
                user: {
                    id: user.id,
                    username: user.username,
                    full_name: user.full_name,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (error) {
        console.error('Login endpoint genel hata:', error);
        res.status(500).json({ error: 'Login endpoint genel hata' });
    }
});

// Kullanıcıları getir (sadece admin)
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
    console.log('Kullanıcılar isteği alındı');
    
    const query = `
        SELECT id, username, email, full_name, role, status, created_at
        FROM users 
        ORDER BY created_at DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Kullanıcılar getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        
        console.log('Bulunan kullanıcı sayısı:', rows ? rows.length : 0);
        console.log('Kullanıcılar:', rows);
        
        if (!rows) {
            console.log('Kullanıcı tablosu boş, boş dizi döndürülüyor');
            res.json([]);
            return;
        }
        
        res.json(rows);
    });
});

// Tekil kullanıcı getir (sadece admin)
app.get('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const query = `
        SELECT id, username, email, full_name, role, status, created_at
        FROM users 
        WHERE id = ?
    `;
    
    db.get(query, [req.params.id], (err, row) => {
        if (err) {
            console.error('Kullanıcı getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (!row) {
            res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            return;
        }
        res.json(row);
    });
});

// Kullanıcı ekle (sadece admin)
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    const { username, password, email, full_name, role, status } = req.body;
    
    try {
        // Şifreyi hash'le
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const query = `
            INSERT INTO users (username, password, email, full_name, role, status)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        
        db.run(query, [username, hashedPassword, email, full_name, role, status ? 1 : 0], function(err) {
            if (err) {
                console.error('Kullanıcı eklenirken hata oluştu:', err);
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ 
                id: this.lastID,
                message: 'Kullanıcı başarıyla eklendi'
            });
        });
    } catch (error) {
        console.error('Şifre hash\'leme hatası:', error);
        res.status(500).json({ error: 'Kullanıcı eklenirken bir hata oluştu' });
    }
});

// Kullanıcı güncelle (sadece admin)
app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const { username, email, full_name, role, status } = req.body;
    
    const query = `
        UPDATE users 
        SET username = ?, email = ?, full_name = ?, role = ?, status = ?
        WHERE id = ?
    `;
    
    db.run(query, [username, email, full_name, role, status ? 1 : 0, req.params.id], function(err) {
        if (err) {
            console.error('Kullanıcı güncellenirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            return;
        }
        res.json({ message: 'Kullanıcı başarıyla güncellendi' });
    });
});

// Kullanıcı sil (sadece admin)
app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const query = `
        DELETE FROM users 
        WHERE id = ?
    `;
    
    db.run(query, [req.params.id], function(err) {
        if (err) {
            console.error('Kullanıcı silinirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            return;
        }
        res.json({ message: 'Kullanıcı başarıyla silindi' });
    });
});

// Duyuruları getir
app.get('/api/announcements', (req, res) => {
    const query = `
        SELECT * FROM announcements 
        WHERE status = 1 
        ORDER BY publish_date DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Duyurular getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows || []);
    });
});

// Haberleri getir
app.get('/api/news', (req, res) => {
    const query = `
        SELECT * FROM news 
        WHERE status = 1 
        ORDER BY publish_date DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Haberler getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows || []);
    });
});

// Galeri görsellerini getir
app.get('/api/gallery', (req, res) => {
    console.log('Galeri görselleri isteği alındı');
    
    const query = `
        SELECT * FROM gallery 
        WHERE status = 1 
        ORDER BY created_at DESC
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Galeri görselleri getirilirken hata oluştu:', err);
            return res.status(500).json({ error: 'Galeri görselleri getirilemedi' });
        }

        if (!rows || rows.length === 0) {
            console.log('Galeri görseli bulunamadı');
            return res.json([]);
        }

        console.log(`${rows.length} adet galeri görseli bulundu`);
        res.json(rows);
    });
});

// Galeri görseli ekle
app.post('/api/gallery', authenticateToken, requireEditorOrAdmin, (req, res) => {
    console.log('Galeri görseli ekleme isteği alındı:', req.body);
    console.log('Dosyalar:', req.files);

    const { title, description, category, status } = req.body;
    const image = req.files ? req.files.image : null;

    if (!title || !category || !image) {
        console.error('Eksik veri:', { title, category, image });
        return res.status(400).json({ error: 'Başlık, kategori ve görsel gereklidir' });
    }

    // Görseli kaydet
    const imagePath = `/uploads/${Date.now()}-${image.name}`;
    const fullPath = path.join(__dirname, imagePath);

    image.mv(fullPath, (err) => {
        if (err) {
            console.error('Görsel kaydedilirken hata oluştu:', err);
            return res.status(500).json({ error: 'Görsel kaydedilemedi' });
        }

        // Veritabanına kaydet
        const query = `
            INSERT INTO gallery (title, description, image, category, status)
            VALUES (?, ?, ?, ?, ?)
        `;

        db.run(query, [title, description, imagePath, category, status ? 1 : 0], function(err) {
            if (err) {
                console.error('Galeri görseli eklenirken hata oluştu:', err);
                return res.status(500).json({ error: 'Görsel veritabanına eklenemedi' });
            }

            console.log('Görsel başarıyla eklendi, ID:', this.lastID);
            res.json({ 
                id: this.lastID,
                message: 'Görsel başarıyla eklendi'
            });
        });
    });
});

// Galeri görseli güncelle
app.put('/api/gallery/:id', authenticateToken, requireEditorOrAdmin, (req, res) => {
    const { title, description, category, status } = req.body;
    const image = req.files ? req.files.image : null;

    if (!title || !category) {
        return res.status(400).json({ error: 'Başlık ve kategori gereklidir' });
    }

    let query = `
        UPDATE gallery 
        SET title = ?, description = ?, category = ?, status = ?
    `;
    let params = [title, description, category, status ? 1 : 0];

    // Eğer yeni görsel yüklendiyse
    if (image) {
        const imagePath = `/uploads/${Date.now()}-${image.name}`;
        image.mv(`.${imagePath}`, (err) => {
            if (err) {
                console.error('Görsel kaydedilirken hata oluştu:', err);
                return res.status(500).json({ error: 'Görsel kaydedilemedi' });
            }

            query += ', image = ?';
            params.push(imagePath);
            params.push(req.params.id);

            db.run(query + ' WHERE id = ?', params, function(err) {
                if (err) {
                    console.error('Galeri görseli güncellenirken hata oluştu:', err);
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json({ message: 'Görsel başarıyla güncellendi' });
            });
        });
    } else {
        params.push(req.params.id);
        db.run(query + ' WHERE id = ?', params, function(err) {
            if (err) {
                console.error('Galeri görseli güncellenirken hata oluştu:', err);
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ message: 'Görsel başarıyla güncellendi' });
        });
    }
});

// Galeri görseli sil
app.delete('/api/gallery/:id', authenticateToken, requireEditorOrAdmin, (req, res) => {
    const query = `
        DELETE FROM gallery 
        WHERE id = ?
    `;
    
    db.run(query, [req.params.id], function(err) {
        if (err) {
            console.error('Galeri görseli silinirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Görsel bulunamadı' });
            return;
        }
        res.json({ message: 'Görsel başarıyla silindi' });
    });
});

// Duyuru ekle
app.post('/api/announcements', (req, res) => {
    const { title, content, category, publish_date, status } = req.body;
    
    const query = `
        INSERT INTO announcements (title, content, category, publish_date, status, created_by)
        VALUES (?, ?, ?, ?, ?, 1)
    `;
    
    db.run(query, [title, content, category, publish_date, status ? 1 : 0], function(err) {
        if (err) {
            console.error('Duyuru ekleme hatası:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ 
            id: this.lastID,
            message: 'Duyuru başarıyla eklendi'
        });
    });
});

// Haber ekle
app.post('/api/news', (req, res) => {
    const { title, content, category, publish_date, status } = req.body;
    
    const query = `
        INSERT INTO news (title, content, category, publish_date, status, created_by)
        VALUES (?, ?, ?, ?, ?, 1)
    `;
    
    db.run(query, [title, content, category, publish_date, status ? 1 : 0], function(err) {
        if (err) {
            console.error('Haber eklenirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ 
            id: this.lastID,
            message: 'Haber başarıyla eklendi'
        });
    });
});

// Haber güncelle
app.put('/api/news/:id', (req, res) => {
    const { title, content, category, publish_date, status } = req.body;
    
    const query = `
        UPDATE news 
        SET title = ?, content = ?, category = ?, publish_date = ?, status = ?
        WHERE id = ?
    `;
    
    db.run(query, [title, content, category, publish_date, status ? 1 : 0, req.params.id], function(err) {
        if (err) {
            console.error('Haber güncellenirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Haber bulunamadı' });
            return;
        }
        res.json({ message: 'Haber başarıyla güncellendi' });
    });
});

// Haber sil
app.delete('/api/news/:id', (req, res) => {
    const query = `
        DELETE FROM news 
        WHERE id = ?
    `;
    
    db.run(query, [req.params.id], function(err) {
        if (err) {
            console.error('Haber silinirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Haber bulunamadı' });
            return;
        }
        res.json({ message: 'Haber başarıyla silindi' });
    });
});

// Token'ı geçersiz kılma endpoint'i
app.post('/api/logout', authenticateToken, (req, res) => {
    // Token'ı blacklist'e ekleyebilir veya client tarafında silinebilir
    res.json({ message: 'Başarıyla çıkış yapıldı' });
});

// Ziyaretçi sayısını artır
app.post('/api/visitors/increment', (req, res) => {
    db.run(`UPDATE visitors SET count = count + 1, last_updated = CURRENT_TIMESTAMP WHERE id = 1`, function(err) {
        if (err) {
            console.error('Ziyaretçi sayısı artırılırken hata:', err);
            return res.status(500).json({ error: 'Ziyaretçi sayısı artırılamadı' });
        }
        res.json({ success: true });
    });
});

// Ziyaretçi sayısını getir
app.get('/api/visitors', (req, res) => {
    db.get('SELECT count, last_updated FROM visitors WHERE id = 1', (err, row) => {
        if (err) {
            console.error('Ziyaretçi sayısı alınırken hata:', err);
            return res.status(500).json({ error: 'Ziyaretçi sayısı alınamadı' });
        }
        res.json(row || { count: 0, last_updated: new Date() });
    });
});

// Online kullanıcı sayısını getir
app.get('/api/online-users', (req, res) => {
    res.json({ count: onlineUsers.size });
});

// Admin klasörü altındaki sayfalar için route'lar
app.get('/admin/haberler', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'haberler.html'));
});
app.get('/admin/haber-ekle', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'haber-ekle.html'));
});
app.get('/admin/duyurular', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'duyurular.html'));
});
app.get('/admin/duyuru-ekle', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'duyuru-ekle.html'));
});
app.get('/admin/galeri', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'galeri.html'));
});
app.get('/admin/galeri-ekle', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'galeri-ekle.html'));
});
app.get('/admin/giris', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});
app.get('/admin/yonetim', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});

// Ana dizindeki sayfalar için route'lar
app.get(['/','/home'], (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/haberler', (req, res) => {
    res.sendFile(path.join(__dirname, 'haberler.html'));
});
app.get('/duyurular', (req, res) => {
    res.sendFile(path.join(__dirname, 'duyurular.html'));
});
app.get('/galeri', (req, res) => {
    res.sendFile(path.join(__dirname, 'galeri.html'));
});

// Sunucuyu başlat
app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor`);
}); 
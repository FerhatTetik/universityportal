const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const JWT_SECRET = 'gizli-anahtar-123'; // Gerçek uygulamada bu değer güvenli bir şekilde saklanmalı

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

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
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Kullanıcı adı ve şifre gereklidir' });
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    
    db.get(query, [username], async (err, user) => {
        if (err) {
            console.error('Login hatası:', err);
            return res.status(500).json({ error: 'Sunucu hatası' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
        }

        // Şifre kontrolü
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
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

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                full_name: user.full_name,
                email: user.email,
                role: user.role
            }
        });
    });
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
    const query = `
        SELECT * FROM gallery 
        WHERE status = 1 
        ORDER BY created_at DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Galeri görselleri getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows || []);
    });
});

// Tekil galeri görseli getir
app.get('/api/gallery/:id', authenticateToken, requireEditorOrAdmin, (req, res) => {
    const query = `
        SELECT * FROM gallery 
        WHERE id = ?
    `;
    
    db.get(query, [req.params.id], (err, row) => {
        if (err) {
            console.error('Galeri görseli getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (!row) {
            res.status(404).json({ error: 'Görsel bulunamadı' });
            return;
        }
        res.json(row);
    });
});

// Yeni galeri görseli ekle
app.post('/api/gallery', authenticateToken, requireEditorOrAdmin, (req, res) => {
    const { title, description, image, category, status } = req.body;
    
    const query = `
        INSERT INTO gallery (title, description, image, category, status)
        VALUES (?, ?, ?, ?, ?)
    `;
    
    db.run(query, [title, description, image, category, status], function(err) {
        if (err) {
            console.error('Galeri görseli eklenirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({
            id: this.lastID,
            title,
            description,
            image,
            category,
            status
        });
    });
});

// Galeri görseli güncelle
app.put('/api/gallery/:id', authenticateToken, requireEditorOrAdmin, (req, res) => {
    const { title, description, image, category, status } = req.body;
    
    const query = `
        UPDATE gallery 
        SET title = ?, description = ?, image = ?, category = ?, status = ?
        WHERE id = ?
    `;
    
    db.run(query, [title, description, image, category, status, req.params.id], function(err) {
        if (err) {
            console.error('Galeri görseli güncellenirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Görsel bulunamadı' });
            return;
        }
        res.json({
            id: req.params.id,
            title,
            description,
            image,
            category,
            status
        });
    });
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

// Sunucuyu başlat
app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor`);
}); 
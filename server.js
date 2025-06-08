const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
const port = 3000;

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
                category TEXT NOT NULL,
                image TEXT,
                status INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        `);
    }
});

// Hata yönetimi middleware'i
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Bir hata oluştu!' });
});

// Kullanıcıları getir
app.get('/api/users', (req, res) => {
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
        res.json(rows);
    });
});

// Tekil kullanıcı getir
app.get('/api/users/:id', (req, res) => {
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

// Kullanıcı ekle
app.post('/api/users', (req, res) => {
    const { username, password, email, full_name, role, status } = req.body;
    
    const query = `
        INSERT INTO users (username, password, email, full_name, role, status)
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    db.run(query, [username, password, email, full_name, role, status ? 1 : 0], function(err) {
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
});

// Kullanıcı güncelle
app.put('/api/users/:id', (req, res) => {
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

// Kullanıcı sil
app.delete('/api/users/:id', (req, res) => {
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
    db.all('SELECT * FROM announcements', [], (err, rows) => {
        if (err) {
            console.error('Duyurular getirme hatası:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Haberleri getir
app.get('/api/news', (req, res) => {
    const query = `
        SELECT * FROM news 
        ORDER BY publish_date DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Haberler getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Tekil haber getir
app.get('/api/news/:id', (req, res) => {
    const query = `
        SELECT * FROM news 
        WHERE id = ?
    `;
    
    db.get(query, [req.params.id], (err, row) => {
        if (err) {
            console.error('Haber getirilirken hata oluştu:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        if (!row) {
            res.status(404).json({ error: 'Haber bulunamadı' });
            return;
        }
        res.json(row);
    });
});

// Galeri görsellerini getir
app.get('/api/gallery', (req, res) => {
    db.all('SELECT * FROM gallery', [], (err, rows) => {
        if (err) {
            console.error('Galeri getirme hatası:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
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

// Sunucuyu başlat
app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor`);
}); 
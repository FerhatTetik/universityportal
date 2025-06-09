import sqlite3
import datetime
import os

# Eğer veritabanı dosyası varsa sil
if os.path.exists('campus_portal.db'):
    os.remove('campus_portal.db')

# Veritabanı bağlantısı
conn = sqlite3.connect('campus_portal.db')
cursor = conn.cursor()

# Kullanıcılar tablosu
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    avatar TEXT,
    status BOOLEAN DEFAULT 1,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# Duyurular tablosu
cursor.execute('''
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    publish_date DATE NOT NULL,
    status BOOLEAN DEFAULT 1,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
)
''')

# Haberler tablosu
cursor.execute('''
CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    image TEXT NOT NULL,
    category TEXT NOT NULL,
    publish_date DATE NOT NULL,
    status BOOLEAN DEFAULT 1,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
)
''')

# Galeri tablosu
cursor.execute('''
CREATE TABLE IF NOT EXISTS gallery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    image TEXT NOT NULL,
    category TEXT NOT NULL,
    status BOOLEAN DEFAULT 1,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
)
''')

# Örnek kullanıcılar
users = [
    ('Ahmet Yılmaz', 'ahmet@example.com', 'hashed_password_1', 'admin', 'images/avatar1.jpg', 1, datetime.datetime.now()),
    ('Ayşe Demir', 'ayse@example.com', 'hashed_password_2', 'editor', 'images/avatar2.jpg', 1, datetime.datetime.now()),
    ('Mehmet Kaya', 'mehmet@example.com', 'hashed_password_3', 'user', 'images/avatar3.jpg', 0, datetime.datetime.now())
]

cursor.executemany('''
INSERT INTO users (name, email, password, role, avatar, status, last_login)
VALUES (?, ?, ?, ?, ?, ?, ?)
''', users)

# Örnek duyurular
announcements = [
    ('Akademik Takvim Güncellemesi', 'Yeni akademik takvim yayınlanmıştır.', 'Akademik', '2024-03-20', 1, 1),
    ('Öğrenci Kulüpleri Toplantısı', 'Tüm kulüp başkanları katılım göstermelidir.', 'Etkinlik', '2024-03-19', 1, 1),
    ('Kütüphane Çalışma Saatleri', 'Final dönemi için kütüphane çalışma saatleri güncellenmiştir.', 'Genel', '2024-03-18', 0, 2)
]

cursor.executemany('''
INSERT INTO announcements (title, content, category, publish_date, status, created_by)
VALUES (?, ?, ?, ?, ?, ?)
''', announcements)

# Örnek haberler
news = [
    ('Uluslararası Araştırma Projesi', 'Üniversitemiz yeni bir uluslararası projeye imza attı.', 'images/news1.jpg', 'Akademik', '2024-03-20', 1, 1),
    ('Yeni Akademik Programlar', 'Üniversitemiz 3 yeni lisans programı açıyor.', 'images/news2.jpg', 'Akademik', '2024-03-19', 1, 2),
    ('Öğrenci Projeleri Sergisi', 'Mühendislik fakültesi öğrenci projeleri sergisi düzenleniyor.', 'images/news3.jpg', 'Etkinlik', '2024-03-18', 0, 1)
]

cursor.executemany('''
INSERT INTO news (title, content, image, category, publish_date, status, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?)
''', news)

# Değişiklikleri kaydet ve bağlantıyı kapat
conn.commit()
conn.close()

print("Veritabanı başarıyla oluşturuldu ve örnek veriler eklendi.") 
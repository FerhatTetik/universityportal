# Kampüs Portalı

Bu proje, bir üniversite kampüsü için yönetim portalı uygulamasıdır. Duyurular, haberler, galeri ve kullanıcı yönetimi gibi temel özellikleri içerir.

## Özellikler

- 📢 Duyuru Yönetimi
- 📰 Haber Yönetimi
- 🖼️ Galeri Yönetimi
- 👥 Kullanıcı Yönetimi
- 🔐 Rol Tabanlı Yetkilendirme
- 📱 Responsive Tasarım

## Gereksinimler

- Node.js (v14 veya üzeri)
- SQLite3
- Modern bir web tarayıcısı

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/kullaniciadi/kampus-portali.git
cd kampus-portali
```

2. Gerekli npm paketlerini yükleyin:
```bash
npm install
```

3. Veritabanını oluşturun:
```bash
node db_setup.js
```

4. Sunucuyu başlatın:
```bash
node server.js
```

## Veritabanı Yapısı

Proje SQLite veritabanı kullanmaktadır. Veritabanı şeması şu tabloları içerir:

- `users`: Kullanıcı bilgileri
- `announcements`: Duyurular
- `news`: Haberler
- `gallery`: Galeri görselleri

## API Endpoint'leri

### Kullanıcılar
- `GET /api/users`: Tüm kullanıcıları listeler
- `GET /api/users/:id`: Tekil kullanıcı bilgilerini getirir
- `POST /api/users`: Yeni kullanıcı ekler
- `PUT /api/users/:id`: Kullanıcı bilgilerini günceller
- `DELETE /api/users/:id`: Kullanıcıyı siler

### Duyurular
- `GET /api/announcements`: Tüm duyuruları listeler
- `GET /api/announcements/:id`: Tekil duyuru bilgilerini getirir
- `POST /api/announcements`: Yeni duyuru ekler
- `PUT /api/announcements/:id`: Duyuru bilgilerini günceller
- `DELETE /api/announcements/:id`: Duyuruyu siler

### Haberler
- `GET /api/news`: Tüm haberleri listeler
- `GET /api/news/:id`: Tekil haber bilgilerini getirir
- `POST /api/news`: Yeni haber ekler
- `PUT /api/news/:id`: Haber bilgilerini günceller
- `DELETE /api/news/:id`: Haberi siler

### Galeri
- `GET /api/gallery`: Tüm galeri öğelerini listeler
- `GET /api/gallery/:id`: Tekil galeri öğesi bilgilerini getirir
- `POST /api/gallery`: Yeni galeri öğesi ekler
- `PUT /api/gallery/:id`: Galeri öğesi bilgilerini günceller
- `DELETE /api/gallery/:id`: Galeri öğesini siler

## Kullanım

1. Tarayıcınızda `http://localhost:3001` adresine gidin
2. Admin paneline erişmek için `http://localhost:3001/admin` adresini kullanın
3. Varsayılan admin kullanıcısı:
   - E-posta: admin@example.com
   - Şifre: admin123

## Klasör Yapısı

```
kampus-portali/
├── admin/                 # Admin panel dosyaları
│   ├── dashboard.html
│   ├── duyurular.html
│   ├── haberler.html
│   ├── galeri.html
│   └── kullanicilar.html
├── images/               # Görsel dosyaları
├── css/                 # Stil dosyaları
├── js/                  # JavaScript dosyaları
├── server.js           # Ana sunucu dosyası
├── db_setup.js         # Veritabanı kurulum dosyası
└── package.json        # Proje bağımlılıkları
```

## Güvenlik

- Tüm şifreler SHA-256 ile hashlenerek saklanır
- API istekleri için CORS koruması vardır
- Rol tabanlı yetkilendirme sistemi kullanılır

## Geliştirme

1. Yeni bir özellik eklemek için:
   - İlgili API endpoint'ini `server.js` dosyasına ekleyin
   - Gerekli veritabanı tablosunu oluşturun
   - Frontend arayüzünü güncelleyin

2. Hata ayıklama için:
   - Sunucu loglarını kontrol edin
   - Tarayıcı konsolunu inceleyin
   - Veritabanı sorgularını test edin

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## İletişim

Sorularınız veya önerileriniz için:
- E-posta: ornek@email.com
- GitHub Issues: [Proje Issues Sayfası](https://github.com/kullaniciadi/kampus-portali/issues) 
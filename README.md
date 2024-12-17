# Advanced Guard Discord Botu

## 🛡️ Gelişmiş Discord Sunucu Güvenlik ve Moderasyon Botu

### 🌟 Proje Açıklaması
Bu Discord botu, sunucunuzun güvenliğini ve moderasyonunu en üst düzeyde sağlamak için gelişmiş özellikler sunar. Yapay zeka destekli filtreleme, güvenlik izleme ve otomatik moderasyon araçları ile sunucunuzun sağlıklı ve güvenli kalmasına yardımcı olur.

### ✨ Temel Özellikler

#### 1. İçerik Filtreleme
- Gelişmiş yapay zeka algoritmaları ile türkçe küfür ve uygunsuz içerik tespiti
- Dinamik benzerlik eşiği ile esnek filtreleme
- Otomatik cezalandırma sistemi (uyarı, susturma, geçici yasaklama)

#### 2. Sunucu Güvenliği
- Sunucu ayarlarındaki değişikliklerin anlık izlenmesi
- Yetkisiz değişikliklerin otomatik engellenmesi
- Düzenli sunucu yapılandırma yedeklemeleri

#### 3. Kullanıcı Davranış Analizi
- Spam ve flood koruması
- Şüpheli hesap tespiti
- Otomatik müdahale mekanizmaları

#### 4. Kapsamlı Raporlama
- Tüm güvenlik olaylarının detaylı kaydedilmesi
- Özel log kanalı bildirimleri
- Şeffaf ve izlenebilir güvenlik yönetimi

### 🚀 Kurulum

#### Gereksinimler
- Python 3.8 veya üzeri
- Discord hesabı
- Discord geliştirici portalından alınmış bot tokeni

#### Kurulum Adımları
1. Depoyu klonlayın
2. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. `config.py` dosyasını düzenleyerek bot ayarlarınızı yapın
4. Bot tokeninizi güvenli bir şekilde yapılandırın

### ⚙️ Yapılandırma
- `config.py`: Bot davranışlarını özelleştirme
- `profanity_list.txt`: Küfür listesi yönetimi
- `bot_config.json`: Sunucu özel ayarları

### 🔒 Güvenlik Önerileri
- Bot tokeninizi asla paylaşmayın
- Log kanallarını düzenli olarak kontrol edin
- Güvenilir kullanıcıları whitelist'e ekleyin

### 📦 Kullanılan Teknolojiler
- Discord.py
- FuzzyWuzzy
- TensorFlow
- Numpy
- Pandas

### 🤝 Katkıda Bulunma
Hata bildirimleri ve öneriler için GitHub üzerinden issue açabilirsiniz.

### 📝 Lisans
GPL-3.0 Lisansı altında yayınlanmıştır.

### 💡 Destek
Herhangi bir sorun yaşarsanız lütfen proje issue sayfasından destek alın.

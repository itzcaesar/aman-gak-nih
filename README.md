# AmanGakNih.id

**AmanGakNih.id** adalah aplikasi web sederhana untuk mengecek keamanan sebuah URL/Website, dengan fokus pada deteksi phishing dan penipuan yang menargetkan pengguna Indonesia.

## 🚀 Fitur MVP

1.  **Analisa Domain**: Cek umur domain (Domain baru < 30 hari ditandai berisiko).
2.  **Cek SSL/HTTPS**: Verifikasi sertifikat SSL dan validitasnya.
3.  **Deteksi Heuristik**: Mencari pola URL mencurigakan (typosquatting, keyword bank, dll).
4.  **Brand Detector**: Mendeteksi jika website mencoba meniru brand populer (BCA, BRI, Google, dll) tanpa menggunakan domain resmi.
5.  **Google Safe Browsing**: Integrasi dengan API Google untuk cek database malware/phishing.
6.  **Skor Transparan**: Memberikan skor 0-100 dengan penjelasan detail untuk setiap sinyal.

## 🛠️ Teknologi

-   **Laravel 11**
-   **MySQL** (Database)
-   **Redis** (Queue & Caching)
-   **Vanilla CSS** (Premium Dark Theme + Glassmorphism)

## 📦 Cara Install & Menjalankan

### Prasyarat
- PHP 8.2+
- Composer
- MySQL
- Redis Server

### Langkah Instalasi
1. Clone repository:
   ```bash
   git clone https://github.com/itzcaesar/aman-gak-nih.git
   cd aman-gak-nih
   ```

2. Install dependencies:
   ```bash
   composer install
   ```

3. Setup `.env`:
   ```bash
   copy .env.example .env
   # Edit database credentials
   # Tambahkan GOOGLE_SAFE_BROWSING_KEY jika punya
   ```

4. Generate Key & Migrate:
   ```bash
   php artisan key:generate
   php artisan migrate --seed
   ```

5. Jalankan Service (Gunakan `start.bat` untuk Windows):
   ```bash
   php artisan serve
   php artisan queue:work
   ```

## ⚖️ Logika Scoring

Sistem menggunakan **Base Score 60**. 
-   **Sinyal Positif** (SSL Valid, Domain Tua, Safe Browsing Clean) menambah skor.
-   **Sinyal Negatif** (No HTTPS, Domain Baru, Keyword Phishing, Impersonasi) mengurangi skor.

**Level Risiko:**
-   **0 - 39**: ❌ **Berbahaya**
-   **40 - 69**: ⚠️ **Mencurigakan**
-   **70 - 100**: ✅ **Relatif Aman**

## 📝 Disclaimer

Aplikasi ini menggunakan metode heuristik dan database publik untuk estimasi keamanan. **Hasil tidak dijamin 100% akurat.** Selalu gunakan penilaian pribadi sebelum memasukkan data sensitif.

---
Dibuat dengan ❤️ untuk Indonesia yang lebih aman.

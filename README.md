<div align="center">

# 🛡️ AmanGakNih.id

**Aplikasi Analisa Keamanan Website & Deteksi Phishing**

[![Laravel](https://img.shields.io/badge/Laravel-12-FF2D20?style=for-the-badge&logo=laravel&logoColor=white)](https://laravel.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Inertia](https://img.shields.io/badge/Inertia.js-Spawn-9553E9?style=for-the-badge&logo=inertia&logoColor=white)](https://inertiajs.com)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)

*Mendeteksi website berbahaya, penipuan, dan phishing dengan heuristik cerdas dan integrasi real-time untuk pengguna Indonesia.*

</div>

---

## 🚀 Fitur Unggulan

| Fitur | Deskripsi |
| :--- | :--- |
| **🔍 Analisa Domain** | Memeriksa umur domain. Domain baru (< 30 hari) ditandai sebagai berisiko tinggi. |
| **🔒 Cek SSL/HTTPS** | Verifikasi sertifikat SSL dan memastikan koneksi terenkripsi. |
| **🧠 Deteksi Heuristik** | Mendeteksi pola URL mencurigakan seperti *typosquatting* atau penggunaan *keyword bank*. |
| **🏢 Brand Detector** | Mengenali percobaan peniruan brand besar (BCA, BRI, Google, dll) pada domain non-resmi. |
| **🛡️ Google Safe Browsing & VIRUS TOTAL** | Integrasi API Google Safe Browsing & Virus Total untuk mencocokkan URL dengan database malware/phishing global. |
| **📊 Skor Transparan** | Memberikan skor risiko **0-100** dengan penjelasan detail untuk setiap sinyal yang ditemukan. |
| **🎨 Tampilan Futuristik** | Antarmuka bertema Matrix dengan latar belakang animasi kode, efek *glitch*, dan visual cyberpunk yang responsif. |
| **⚡ Performa Tinggi** | Proses scanning dioptimalkan dengan eksekusi paralel (async), mempercepat pengumpulan data dari berbagai sumber API. |

## 🛠️ Teknologi Utama

-   **Backend**: Laravel 12 (PHP 8.2+)
-   **Frontend**: React 18, Inertia.js
-   **Styling**: Tailwind CSS v4, Framer Motion
-   **Database**: MySQL, Redis

## 📦 Panduan Instalasi

Ikuti langkah berikut untuk menjalankan aplikasi di komputer lokal Anda:

### 1. Download Source Code
```bash
git clone https://github.com/itzcaesar/aman-gak-nih.git
cd aman-gak-nih
```

### 2. Install Dependencies
Pastikan **Composer**, **PHP**, dan **Node.js** sudah terinstall.
```bash
composer install
npm install
```

### 3. Konfigurasi Environment
Salin file `.env` dan atur koneksi database Anda.
```bash
copy .env.example .env
```
> **Tip**: Tambahkan keys berikut di .env untuk hasil scan yang lebih akurat:
> - `GOOGLE_SAFE_BROWSING_KEY`
> - `VIRUSTOTAL_API_KEY`

### 4. Setup Database
Generate app key dan jalankan migrasi database serta seeder.
```bash
php artisan key:generate
php artisan migrate --seed
```

### 5. Jalankan Aplikasi ⚡
Untuk kemudahan, gunakan script `start.bat` yang akan menjalankan Laravel Serve, Queue Worker, dan Vite sekaligus.

```bash
./start.bat
```

Atau jalankan secara manual di terminal terpisah:
```bash
# Terminal 1
php artisan serve

# Terminal 2
php artisan queue:work

# Terminal 3
npm run dev
```

---

## ⚖️ Sistem Scoring

Sistem menggunakan **Base Score 80** yang akan bertambah atau berkurang berdasarkan sinyal dan konsensus vendor:

<div align="center">

| Skor | Level Risiko | Indikator |
| :---: | :--- | :--- |
| **0 - 39** | 🚨 **HIGH RISK** | > 10 Vendor Security Flag, Malware, atau Impersonasi Brand. |
| **40 - 74** | ⚠️ **NEUTRAL / UNKNOWN** | Domain baru, < 5 Vendor Flag (False Positive), atau data kurang. |
| **75 - 100** | ✅ **LIKELY SAFE** | Domain terpercaya, SSL valid, dan Konsensus Komunitas Positif. |

</div>

> **Dynamic Scoring**: Penalti poin kini bersifat dinamis berdasarkan jumlah vendor keamanan yang mendeteksi ancaman (-5 poin per vendor), memastikan situs baru dengan sedikit *false positive* tidak langsung dianggap berbahaya.

## 📝 Disclaimer

Aplikasi ini menggunakan metode heuristik dan database publik untuk estimasi keamanan. **Hasil tidak dijamin 100% akurat.** Selalu gunakan penilaian pribadi dan kewaspadaan ekstra sebelum memasukkan data sensitif di internet.

---


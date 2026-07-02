[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Firewall aplikasi web open-source yang ringan

[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)
[![Last commit](https://img.shields.io/github/last-commit/samwafgo/SamWaf?style=flat-square&color=blue&logo=github)](https://github.com/samwafgo/SamWaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/samwaf/samwaf?style=flat-square&color=blue&label=Docker+Image+Pulls)](https://hub.docker.com/r/samwaf/samwaf)
[![Release Downloads](https://img.shields.io/github/downloads/samwafgo/samwaf/total?style=flat-square&color=blue&label=Release+Downloads)](https://github.com/samwafgo/SamWaf/releases)
[![Gitee](https://img.shields.io/badge/Gitee-blue?style=flat-square&logo=Gitee)](https://gitee.com/samwaf/SamWaf)
[![GitHub stars](https://img.shields.io/github/stars/samwafgo/SamWaf?style=flat-square&logo=Github)](https://github.com/samwafgo/SamWaf)
[![Gitee star](https://gitee.com/samwaf/SamWaf/badge/star.svg?theme=gray)](https://gitee.com/samwaf/SamWaf)
[![Atomgit star](https://atomgit.com/SamSafe/SamWaf/star/badge.svg)](https://atomgit.com/SamSafe/SamWaf)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
</div>

  
## Motivasi Pengembangan:
- **Ringan**: Awalnya saya menggunakan beberapa produk keamanan berbasis plugin nginx, apache, dan iis untuk proteksi, tetapi bentuk plugin memiliki tingkat coupling yang tinggi.
- **Privatisasi**: Kemudian, sebagian besar beralih ke layanan proteksi cloud, tetapi deployment privat hanya terjangkau bagi perusahaan menengah dan besar, sementara bagi perusahaan kecil dan studio biayanya terasa mahal.
- **Enkripsi Privasi**: Dalam proteksi web, lebih baik data lokal diproses tanpa dikirim ke cloud. Tujuannya adalah membuat alat yang mengenkripsi informasi lokal dan komunikasi jaringan untuk sisi manajemen.
- **DIY**: Selama bertahun-tahun memelihara dan mengembangkan situs web, ada fungsi-fungsi tertentu yang ingin saya tambahkan tetapi tidak dapat diwujudkan.
- **Kesadaran**: Jika webmaster belum pernah menggunakan WAF serupa, sulit untuk memahami siapa yang mengakses situs dan request apa saja yang dibuat hanya dari log atau nginx, apache, IIS, dan sebagainya.

Singkatnya, tujuannya adalah membuat alat yang efektif untuk proteksi situs web atau API guna menangani situasi abnormal dan memastikan situs web serta aplikasi tetap beroperasi secara normal.

# Pengenalan Perangkat Lunak
SamWaf adalah firewall aplikasi web open-source yang ringan untuk perusahaan kecil, studio, dan situs web pribadi. SamWaf mendukung deployment sepenuhnya privat, mengenkripsi data yang disimpan secara lokal, mudah dijalankan, serta mendukung Linux, Windows 64-bit, dan ARM64, dengan image Docker yang tersedia. Secara default, SamWaf menggunakan database SQLite terenkripsi yang tertanam tanpa dependensi eksternal, dan dapat beralih ke MySQL secara opsional.

## Arsitektur

![Arsitektur SamWaf](./docs/images_en/tecDesign.svg)

## Antarmuka
![Ikhtisar Firewall Aplikasi Web SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Tambah Host</td>
        <td align="center">Log Serangan</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Tambah Host"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Log Serangan"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">Daftar Blokir IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="Daftar Blokir IP"/></td>
    </tr>
    <tr>
        <td align="center">Daftar Izin IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="Daftar Izin IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Log Penambahan Skrip Aturan</td>
        <td align="center">Pilih Log</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Log Penambahan Skrip Aturan"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Pilih Log"/></td>
    </tr>
    <tr>
        <td align="center">Detail Log</td>
        <td align="center">Aturan Manual</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Detail Log"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Aturan Manual"/></td>
    </tr>
    <tr>
        <td align="center">Daftar Blokir URL</td>
        <td align="center">Daftar Izin URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="Daftar Blokir URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="Daftar Izin URL"/></td>
    </tr>
</table>

## Fitur Utama

### Dasar
- Kode sepenuhnya open-source (Apache 2.0)
- Deployment sepenuhnya privat; data dienkripsi dan hanya disimpan secara lokal
- Berkas tunggal yang dijalankan dengan sekali klik, ringan tanpa dependensi layanan pihak ketiga (MySQL/Redis bersifat opsional)
- Engine sepenuhnya independen; proteksi tidak bergantung pada IIS atau Nginx
- Dukungan IPv6

### Akses Trafik
- Dukungan HTTP/1.1, HTTP/2, dan HTTP/3 (QUIC)
- Forwarding WebSocket
- Reverse proxy dengan load balancing (weighted round-robin, IP hash, least connections); health check secara otomatis menyingkirkan backend yang tidak sehat
- Aturan path: reverse proxy per path, berkas statis, atau redirect 301/302, dengan protokol backend dan timeout respons yang dapat dikonfigurasi
- Penyajian situs statis
- Forwarding tunnel layer-4 TCP/UDP (dengan kontrol akses IP dan kontrol jendela waktu)
- Caching halaman web
- HTTP Basic Auth untuk akses situs
- Halaman pemblokiran yang dapat disesuaikan

### Proteksi Serangan
- Deteksi injeksi SQL
- Deteksi XSS (cross-site scripting)
- Deteksi RCE (remote command execution)
- Deteksi alat pemindai (scanner)
- Deteksi path traversal
- Deteksi unggahan berkas (ekstensi berbahaya, signature webshell, Content-Type palsu)
- Proteksi CC / rate-limit
- Deteksi crawler / bot palsu (verifikasi reverse-DNS untuk bot mesin pencari)
- Anti-leech (proteksi hotlink)
- Proteksi CSRF (validasi Origin/Referer per situs)
- Penyaringan kata sensitif
- Dukungan rule set OWASP CRS (engine Coraza; aturan dapat diaktifkan/dinonaktifkan/di-override)
- Aturan proteksi yang dapat disesuaikan, mendukung penyuntingan melalui skrip maupun GUI
- Verifikasi manusia: CAPTCHA klik dan proof-of-work Cap.js
- Mode hanya-log: mencatat serangan tanpa memblokir, berguna untuk mengamati dan menyetel aturan

### Kontrol Akses
- Daftar izin / daftar blokir IP
- Daftar izin / daftar blokir URL
- Pemblokiran geografis (database offline bawaan ip2region/GeoIP2, IPv4/IPv6)
- Pemblokiran IP yang terintegrasi dengan firewall OS
- Pemblokiran otomatis saat jumlah kegagalan sebuah IP mencapai ambang batas
- Konfigurasi global sekali klik dan strategi proteksi per situs

### Keamanan Data
- Penyimpanan log terenkripsi
- Log komunikasi terenkripsi
- Masking data (DLP) dengan output privasi data yang ditentukan
- Anti-tamper halaman web (pembelajaran baseline + pemulihan otomatis)
- Penguatan keamanan cookie (HttpOnly/Secure/SameSite)

### Sertifikat SSL
- Pengajuan dan perpanjangan sertifikat SSL secara otomatis (ACME, multi-CA dengan dukungan EAB)
- Multi-sertifikat SNI dan HTTPS multi-port
- Pemeriksaan kedaluwarsa sertifikat SSL secara massal
- Pemuatan sertifikat otomatis

### Operasional & Manajemen
- RBAC akun, autentikasi dua faktor OTP, log login/operasi
- Laporan statistik serta pemantauan sistem/host
- Kebijakan retensi data dengan sharding dan pengarsipan log otomatis
- SQLite (terenkripsi) secara default, MySQL opsional, dengan alat migrasi SQLite→MySQL bawaan
- Upgrade online sekali klik, rolling restart tanpa downtime, dan rollback versi
- Tugas batch, tugas terjadwal, dan pencadangan data
- Open API

### Notifikasi
- Kanal pengiriman melalui Email, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ, dan berkas log

# Petunjuk Penggunaan
**Sangat disarankan untuk melakukan pengujian menyeluruh di lingkungan uji sebelum melakukan deployment ke produksi. Jika terjadi masalah, mohon segera berikan umpan balik.**
## Unduh Versi Terbaru
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Mulai Cepat

### Windows
- Jalankan langsung
```
SamWaf64.exe
```
- Jalankan sebagai layanan (memerlukan hak Administrator)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- instal
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- uninstal
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh uninstall 
```

### Docker
```
docker run -d --name=samwaf-instance \
           --restart always \
           -p 26666:26666 \
           -p 80:80 \
           -p 443:443 \
           -v /path/to/your/conf:/app/conf \
           -v /path/to/your/data:/app/data \
           -v /path/to/your/logs:/app/logs \
           -v /path/to/your/ssl:/app/ssl \
           samwaf/samwaf


```
Detail Docker lebih lanjut https://hub.docker.com/r/samwaf/samwaf

Tag:
- **latest**: Rilis stabil terbaru (disarankan untuk penggunaan produksi).
- **beta**: Versi pengujian terbaru (memungkinkan pengujian fitur baru atau perbaikan bug tertentu).

### Alat Command-Line

| Perintah | Deskripsi |
|---------|-------------|
| `install` / `uninstall` | Menginstal / mencopot layanan sistem |
| `start` / `stop` / `restart` | Memulai / menghentikan / memulai ulang layanan |
| `rolling-restart` | Rolling restart tanpa downtime (mengganti worker tanpa mengganggu trafik) |
| `resetpwd` | Mereset kata sandi administrator |
| `resetotp` | Mereset kode keamanan (OTP) |
| `repairdb` | Memperbaiki database yang rusak |
| `execsql` | Menjalankan pernyataan SQL pada database yang dipilih |
| `migratedb` | Migrasi database offline SQLite → MySQL (`--dry-run` hanya untuk estimasi, `--force` untuk menimpa) |
| `rollback` | Mengembalikan ke versi cadangan sebelumnya |

Contoh: `SamWaf64.exe resetpwd` (di Linux: `./SamWafLinux64 resetpwd`)

## Mulai Akses

http://127.0.0.1:26666

Akun default: admin  Kata sandi default: admin868 (Harap ubah kata sandi default saat login pertama kali)


## Panduan Upgrade

**Catatan: Proses upgrade akan menghentikan layanan, harap lakukan upgrade di luar jam sibuk.**

### Upgrade Otomatis
Jika versi baru tersedia, prompt upgrade akan muncul untuk konfirmasi, sehingga Anda dapat memulai upgrade. Halaman akan dimuat ulang secara otomatis setelah upgrade selesai.

### Upgrade Manual
- Untuk mode jalankan langsung:
    1. Tutup aplikasi.
    2. Unduh program terbaru dan gantikan berkas yang ada, lalu jalankan kembali secara manual.

- Untuk mode layanan:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Catatan**: Upgrade layanan Windows dapat memicu aturan keamanan dari 360 atau Huorong, sehingga berkas baru tidak dapat digantikan secara normal. Dalam kasus ini, Anda dapat mengganti berkas secara manual. Mereka yang memahami area ini dapat membantu menentukan cara penanganan yang tepat.

## Dokumentasi Online

[Dokumentasi Online](https://doc.samwaf.com/)

# Informasi Kode
## Repositori Kode
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Pengenalan dan Kompilasi
Cara Mengompilasi
[Petunjuk Kompilasi](./docs/compile.md)

Manual Online Kompilasi：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Platform yang Telah Diuji dan Didukung
[Platform yang Telah Diuji dan Didukung](./docs/Tested_supported_systems.md)

## Info Lainnya 

- [Pembaruan Database IP](./docs/ipmodify.md)

## Hasil Pengujian
[Hasil Pengujian](./test/attackTest.md)

# Kebijakan Keamanan
[Kebijakan Keamanan](./SECURITY.md)

# Umpan Balik
SamWaf terus berkembang melalui iterasi. Kami menyambut baik umpan balik dan saran.

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- Umpan balik melalui email: samwafgo@gmail.com

# Akun Resmi WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Riwayat Star

[![Grafik Riwayat Star](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Lisensi
SamWaf dilisensikan di bawah Apache License 2.0. Lihat [LICENSE](./LICENSE) untuk detail lebih lanjut.

Untuk pemberitahuan penggunaan perangkat lunak pihak ketiga, lihat [ThirdLicense](./ThirdLicense)

# Kontribusi
 Terima kasih kepada para kontributor berikut!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>

# REKAP LENGKAP PRAKTIKUM KEAMANAN JARINGAN (KAMJAR)
**Materi:** IDS/IPS Suricata, Web Application Security (DVWA), & Attack Simulation  
**Penulis:** Afif Nur Rahman (H1H024016)  
**Target Lab:** Universitas Jenderal Soedirman  
**Catatan Penting:** Seluruh penjelasan perintah dan rules pada dokumen ini bersifat **100% mandiri (self-contained)**. Setiap perintah dan setiap baris rule menyajikan bedah kata-per-kata secara utuh tanpa ada parameter yang dilewati atau disingkat.

---

## DAFTAR ISI
1. [Bedah Lengkap Perintah Terminal VM 1 (Kali Linux - Attacker) Kata per Kata](#1-bedah-lengkap-perintah-terminal-vm-1-kali-linux---attacker)
2. [Bedah Lengkap Perintah Terminal VM 2 (Ubuntu Server - Defender) Kata per Kata](#2-bedah-lengkap-perintah-terminal-vm-2-ubuntu-server---defender)
3. [Bedah Perintah Instalasi Native LAMP Stack & DVWA Kata per Kata](#3-bedah-perintah-instalasi-native-lamp-stack--dvwa)
4. [Bedah Mendalam Encoding URL & Karakter Heksadesimal (%20, %27, %23, %3D, dll)](#4-bedah-mendalam-encoding-url--karakter-heksadesimal)
5. [Bedah Mendalam Sintaks Regex PCRE (Perl-Compatible Regular Expressions)](#5-bedah-mendalam-sintaks-regex-pcre)
6. [Bedah Mendalam TCP Flags & Masking Bit ECN (flags:S,12; dan flags:S;)](#6-bedah-mendalam-tcp-flags--masking-bit-ecn)
7. [Bedah Mendalam Sticky Buffer & Engine Preprocessor Suricata](#7-bedah-mendalam-sticky-buffer--engine-preprocessor-suricata)
8. [Bedah Mendalam Mesin Laju Trafik (Thresholding)](#8-bedah-mendalam-mesin-laju-trafik-thresholding)
9. [Bedah Seluruh Baris Rules Praktikum Kata per Kata (Tanpa Opsi Dilewati)](#9-bedah-seluruh-baris-rules-praktikum)
   - [Rule A: SYN Flood (Bab V Modul - sid:1000001)](#rule-a-syn-flood-bab-v-modul---sid1000001)
   - [Rule B: ICMP Burst (Bab V Modul - sid:1000002)](#rule-b-icmp-burst-bab-v-modul---sid1000002)
   - [Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)](#rule-c-udp-burst-port-53-dns-bab-v-modul---sid1000003)
   - [Rule 1: SQL Injection Tautology Bypass (sid:1000021)](#rule-1-sql-injection-tautology-bypass---sid1000021)
   - [Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)](#rule-2-reflected-xss-event-handler-bypass---sid1000022)
   - [Rule 3: CSRF Unauthorized Password Change (sid:1000023)](#rule-3-csrf-unauthorized-password-change---sid1000023)
   - [Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)](#rule-4-dos-tcp-syn-flood-port-80-dvwa---sid1000024)
   - [Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)](#rule-5-mode-ips---sql-injection-dropped---sid1000021-rev5)
10. [Konseptual Arsitektur: Mode IDS vs Mode IPS](#10-konseptual-arsitektur-mode-ids-vs-mode-ips)
11. [FAQ Ujian Lisan: Menjalankan Suricata Mode IDS vs Memantau Log (`tail -f`)](#11-faq-ujian-lisan-menjalankan-suricata-mode-ids-vs-memantau-log)
12. [Panduan Lengkap Footprinting & OSINT: SpiderFoot v4.0.0](#12-panduan-lengkap-footprinting--osint-spiderfoot-v400)
   - [A. Konsep Dasar Footprinting & Pengintaian OSINT](#a-konsep-dasar-footprinting--pengintaian-osint)
   - [B. Bedah Perintah Instalasi & Troubleshooting Dependensi Kata per Kata](#b-bedah-perintah-instalasi--troubleshooting-dependensi-kata-per-kata)
   - [C. Bedah Konfigurasi 3 Filter pada Halaman New Scan](#c-bedah-konfigurasi-3-filter-pada-halaman-new-scan)
   - [D. Bedah Temuan Dua Target: Cloud Vercel vs On-Premise Kampus](#d-bedah-temuan-dua-target-cloud-vercel-vs-on-premise-kampus)
   - [E. Kueri SQL Forensik Basis Data Internal spiderfoot.db](#e-kueri-sql-forensik-basis-data-internal-spiderfootdb)
   - [F. Bank Pertanyaan Ujian Lisan Seputar SpiderFoot](#f-bank-pertanyaan-ujian-lisan-seputar-spiderfoot)
13. [Panduan Lengkap Cara Mengecek Path dan Lokasi fast.log](#13-panduan-lengkap-cara-mengecek-path-dan-lokasi-fastlog)
   - [A. Metode 1: Memeriksa Berkas Konfigurasi suricata.yaml (Metode Resmi)](#a-metode-1-memeriksa-berkas-konfigurasi-suricatayaml-metode-resmi)
   - [B. Metode 2: Memeriksa Informasi Build Biner Suricata](#b-metode-2-memeriksa-informasi-build-biner-suricata)
   - [C. Metode 3: Mencari Berkas Fisik di Direktori Sistem via find](#c-metode-3-mencari-berkas-fisik-di-direktori-sistem-via-find)
   - [D. Metode 4: Menginspeksi File Descriptor Proses Aktif via lsof (Metode Forensik)](#d-metode-4-menginspeksi-file-descriptor-proses-aktif-via-lsof-metode-forensik)
   - [E. Metode 5: Memeriksa Ukuran dan Izin Berkas via ls -lh](#e-metode-5-memeriksa-ukuran-dan-izin-berkas-via-ls--lh)

---

## 1. BEDAH LENGKAP PERINTAH TERMINAL VM 1 (KALI LINUX - ATTACKER)

---

### A. Perintah DoS TCP SYN Flood Terukur
```bash
sudo hping3 -S -p 80 -c 50 --faster 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Menjalankan perintah dengan hak akses root/administrator tertinggi sistem Linux. Pembuatan soket mentah (*raw socket*) dan perakitan header TCP kustom di tingkat kernel mewajibkan hak akses root.
* **`hping3`**: Program generator dan penganalisis paket jaringan berbasis CLI yang mampu merakit paket IP, TCP, UDP, dan ICMP secara fleksibel.
* **`-S`** (*SYN Flag*): Mengaktifkan secara spesifik bendera kontrol TCP **SYN** (*Synchronize*), yaitu jenis paket inisiasi jabat tangan koneksi baru pada *TCP Three-Way Handshake*.
* **`-p`** (*Destination Port Flag*): Opsi saklar untuk menentukan nomor port tujuan serangan.
* **`80`**: Nilai port tujuan yang diserang, yaitu port standar layanan HTTP tempat web server DVWA berjalan.
* **`-c`** (*Count Flag*): Opsi saklar untuk membatasi jumlah total paket yang dikirimkan.
* **`50`**: Nilai jumlah paket. Mengirimkan tepat 50 paket lalu perintah otomatis berhenti agar server target tidak crash permanen.
* **`--faster`** (*Fast transmission rate*): Parameter pengatur kecepatan pengiriman paket. Mengatur interval kirim menjadi 10 milidetik (10.000 mikrodetik), yang setara dengan **100 paket per detik**.
* **`192.168.2.3`**: Alamat IPv4 tujuan (VM 2 Ubuntu Server sebagai sasaran serangan).

---

### B. Perintah DoS TCP SYN Flood Mode Ekstrem
```bash
sudo hping3 -S -p 80 --flood 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Menjalankan utilitas dengan hak istimewa administrator tertinggi kernel Linux.
* **`hping3`**: Program perakit dan pengirim paket TCP/IP kustom.
* **`-S`** (*SYN Flag*): Menyetel bendera TCP SYN aktif (bernilai 1) pada setiap paket yang keluar.
* **`-p`** (*Destination Port Flag*): Parameter pemilih nomor port tujuan.
* **`80`**: Nomor port layanan web HTTP target.
* **`--flood`** (*Flood Mode*): Mode transmisi paling agresif. Memerintahkan `hping3` mengirimkan paket secepat mungkin sesuai kapasitas maksimal bandwidth antarmuka jaringan tanpa menunggu balasan paket dan tanpa mencetak log balasan ke layar (*no reply processing*).
* **`192.168.2.3`**: Alamat IPv4 server target yang dibanjiri paket.

---

### C. Perintah Menghentikan Paksa Proses Macet
```bash
sudo killall -9 hping3
```
* **`sudo`** (*SuperUser DO*): Memberikan wewenang root untuk mengirimkan sinyal penghentian proses tingkat sistem.
* **`killall`**: Program Linux untuk mengirimkan sinyal terminasi ke semua proses yang berjalan berdasarkan nama programnya (bukan berdasarkan nomor PID).
* **`-9`** (*SIGKILL Signal*): Sinyal pembunuhan mutlak pada kernel Linux. Sinyal nomor 9 tidak dapat ditangkap (*unblockable*), tidak dapat ditunda, dan tidak dapat diabaikan oleh program yang sedang macet di memori.
* **`hping3`**: Nama program target yang dihentikan paksa.

---

### D. Perintah Pengujian Konektivitas ICMP Ping
```bash
ping -c 3 192.168.2.3
```
* **`ping`**: Utilitas penguji keterjangkauan jaringan (*network reachability*) berbasis protokol kendali ICMP (*Internet Control Message Protocol*).
* **`-c`** (*Count Flag*): Menentukan jumlah pengiriman paket permintaan ping.
* **`3`**: Mengirimkan tepat 3 paket *ICMP Echo Request* lalu berhenti otomatis.
* **`192.168.2.3`**: Alamat IP host tujuan yang diuji konektivitasnya.

---

### E. Perintah Eksploitasi Web via CLI (cURL)
```bash
curl -i -s "http://192.168.2.3/dvwa/vulnerabilities/sqli/?id=%27+OR+%271%27%3D%271&Submit=Submit"
```
* **`curl`** (*Client URL*): Program baris perintah untuk mentransfer data menuju atau dari server menggunakan berbagai protokol internet (HTTP, HTTPS, FTP).
* **`-i`** (*Include Headers*): Menampilkan response header HTTP dari server (seperti `HTTP/1.1 200 OK`, `Server: Apache`, `Set-Cookie`) bersamaan dengan isi konten dokumen HTML.
* **`-s`** (*Silent Mode*): Mode senyap yang menyembunyikan meteran indikator kecepatan/persentase transfer data agar tampilan terminal bersih.
* **`"..."`** (*Quoted Target URL*): String alamat URL tujuan yang membawa muatan eksploitasi (*payload*). Tanda petik ganda wajib dipasang agar karakter khusus peramban seperti `?`, `&`, `=`, dan `'` tidak diinterpretasikan salah oleh shell Linux.

---

## 2. BEDAH LENGKAP PERINTAH TERMINAL VM 2 (UBUNTU SERVER - DEFENDER)

---

### A. Validasi Sintaks Konfigurasi Suricata
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk membaca file konfigurasi privat sistem.
* **`suricata`**: Biner aplikasi mesin Intrusion Detection System (IDS).
* **`-T`** (*Test configuration flag*): Mode uji coba sintaks. Suricata akan mengompilasi konfigurasi dan seluruh berkas rules ke memori, memastikan tidak ada galat (error kurung/spasi/variabel), lalu langsung keluar (*exit*) tanpa mengaitkan antarmuka jaringan.
* **`-c`** (*Config file flag*): Parameter penunjuk lokasi berkas konfigurasi utama.
* **`/etc/suricata/suricata.yaml`**: Alamat berkas absolut konfigurasi master Suricata.
* **`-v`** (*Verbose flag*): Menampilkan informasi log inisialisasi secara detail ke layar terminal (langkah alokasi memori, parsing rule, dan thread).

---

### B. Live Reload Rules Tanpa Mematikan Layanan
```bash
sudo suricatasc -c reload-rules
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`suricatasc`** (*Suricata Socket Client*): Utilitas CLI untuk berinteraksi langsung dengan daemon Suricata yang berjalan melalui UNIX domain socket (`suricata-command.socket`).
* **`-c`** (*Command flag*): Parameter penunjuk instruksi perintah yang harus dijalankan soket.
* **`reload-rules`**: String perintah internal yang memerintahkan Suricata membaca ulang file `.rules` dan menukarnya secara atomik di memori (*zero packet loss / zero downtime*).

---

### C. Live Monitoring Log Alert Real-Time
```bash
sudo tail -f /var/log/suricata/fast.log
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk membaca berkas log sistem.
* **`tail`**: Utilitas Linux standar untuk mencetak bagian baris paling akhir dari sebuah berkas teks.
* **`-f`** (*Follow mode flag*): Mengunci terminal dalam status mendengarkan (*listen*). Setiap kali ada baris peringatan serangan baru yang ditulis Suricata, terminal langsung menampilkannya seketika ke layar secara real-time.
* **`/var/log/suricata/fast.log`**: Berkas teks tempat Suricata mencatat alert ringkas satu baris (*single-line alert*).

---

### D. Restart Layanan Daemon Suricata
```bash
sudo systemctl restart suricata
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`systemctl`** (*Systemd Control*): Utilitas pengontrol sistem inisialisasi dan manajer layanan (*systemd*).
* **`restart`**: Menghentikan proses daemon secara total (*SIGTERM*) lalu menyalakannya kembali dari nol.
* **`suricata`**: Nama unit layanan sistem (`suricata.service`).

---

### E. Pemeriksaan Status Kesehatan Layanan Suricata
```bash
sudo systemctl status suricata
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`systemctl`** (*Systemd Control*): Utilitas pengontrol layanan systemd.
* **`status`**: Menampilkan ringkasan status operasional (apakah aktif hijau `active (running)`, PID proses, alokasi memori, dan histori baris log terakhir).
* **`suricata`**: Nama unit layanan sistem (`suricata.service`).

---

### F. Inspeksi Antarmuka Jaringan & Alamat IP
```bash
ip -br a
```
* **`ip`**: Program pengelola antarmuka dan perutean jaringan (paket `iproute2`, pengganti utilitas lama `ifconfig`).
* **`-br`** (*Brief flag*): Menampilkan data dalam format tabel ringkas satu baris per kartu jaringan.
* **`a`** (*Address keyword*): Menampilkan informasi alamat IPv4 dan IPv6 yang terpasang pada antarmuka.

---

### G. Mode IPS: Pengalihan Paket ke Antrean Kernel via Iptables
```bash
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk memodifikasi tabel firewall kernel.
* **`iptables`**: Program firewall paket filter bawaan kernel Linux.
* **`-I`** (*Insert flag*): Menyisipkan aturan di urutan paling awal pada sebuah rantai firewall.
* **`INPUT`**: Nama rantai firewall yang menangani seluruh paket yang datang dari jaringan luar menuju ke server lokal.
* **`-p`** (*Protocol flag*): Menentukan protokol jaringan yang difilter.
* **`tcp`**: Nilai protokol transport TCP.
* **`--dport`** (*Destination Port flag*): Menentukan nomor port tujuan paket.
* **`80`**: Nomor port web server HTTP Apache / DVWA.
* **`-j`** (*Jump target flag*): Menentukan tindakan yang diambil jika paket cocok.
* **`NFQUEUE`** (*Netfilter Queue target*): Membelokkan paket ke antrean memori kernel *Netfilter Queue* agar diperiksa oleh program IPS eksternal (Suricata).
* **`--queue-num`** (*Queue Number flag*): Menentukan nomor antrean spesifik.
* **`0`**: Nilai nomor antrean memori 0.

---

### H. Mode IPS: Menjalankan Suricata Memeriksa Antrean Kernel
```bash
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -v
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk menginspeksi antrean kernel.
* **`suricata`**: Biner aplikasi mesin IDS/IPS Suricata.
* **`-c`** (*Config file flag*): Menentukan lokasi berkas konfigurasi utama.
* **`/etc/suricata/suricata.yaml`**: Berkas konfigurasi master Suricata.
* **`-q`** (*Queue mode flag*): Parameter penentu bahwa Suricata berjalan dalam **Mode IPS Inline** mendengarkan antrean kernel *NFQUEUE*.
* **`0`**: Nilai nomor antrean memori kernel yang diperiksa (antrean nomor 0, sinkron dengan aturan iptables).
* **`-v`** (*Verbose flag*): Menampilkan log operasional secara mendalam ke layar terminal.

---

## 3. BEDAH PERINTAH INSTALASI NATIVE LAMP STACK & DVWA

---

### A. Instalasi Paket Web Server, Database, dan Interpreter PHP
```bash
sudo apt update && sudo apt install -y apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php git
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`apt`** (*Advanced Package Tool*): Program pengelola paket (*package manager*) distro Debian/Ubuntu.
* **`update`**: Menyegarkan kembali indeks daftar paket lokal dari server cermin repositori Ubuntu.
* **`&&`** (*Operator Logika AND*): Operator shell yang memastikan perintah kedua dieksekusi hanya jika perintah pertama berhasil tanpa error (*exit code 0*).
* **`install`**: Subperintah `apt` untuk memasang paket perangkat lunak baru.
* **`-y`** (*Automatic Yes flag*): Menjawab konfirmasi alokasi ruang penyimpanan secara otomatis dengan nilai "Yes".
* **`apache2`**: Paket perangkat lunak web server HTTP Apache versi 2.
* **`mariadb-server`**: Paket sistem manajemen basis data relasional (*RDBMS*) MariaDB (turunan MySQL).
* **`php`**: Interpreter bahasa pemrograman PHP sisi server tempat DVWA berjalan.
* **`php-mysqli`**: Driver ekstensi PHP untuk berkomunikasi dengan basis data MySQL/MariaDB.
* **`php-gd`** (*Graphics Draw*): Ekstensi pustaka PHP untuk memproses grafik dan gambar (avatar/captcha).
* **`libapache2-mod-php`**: Modul integrasi interpreter PHP langsung ke dalam worker web server Apache.
* **`git`**: Perangkat lunak sistem pengontrol versi terdistribusi untuk mengunduh source code DVWA.

---

### B. Masuk ke Direktori Document Root Web
```bash
cd /var/www/html
```
* **`cd`** (*Change Directory*): Perintah dasar shell Linux untuk berpindah direktori kerja aktif.
* **`/var/www/html`**: Jalur direktori standar (*Document Root*) web server Apache di Ubuntu. Seluruh file yang ditaruh di sini dapat diakses via peramban.

---

### C. Kloning Source Code DVWA dari Repositori GitHub
```bash
sudo git clone https://github.com/digininja/DVWA.git dvwa
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk menulis direktori sistem `/var/www/html`.
* **`git`**: Menjalankan biner git.
* **`clone`**: Mengunduh salinan repositori kode sumber secara utuh dari server internet ke komputer lokal.
* **`https://github.com/digininja/DVWA.git`**: Alamat URL repositori resmi proyek DVWA oleh Robin Wood (*digininja*).
* **`dvwa`**: Nama folder lokal tujuan hasil kloning. Alamat web menjadi `http://192.168.2.3/dvwa/`.

---

### D. Menyalin Template Berkas Konfigurasi DVWA
```bash
sudo cp dvwa/config/config.inc.php.dist dvwa/config/config.inc.php
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`cp`** (*Copy*): Utilitas Linux untuk menyalin berkas.
* **`dvwa/config/config.inc.php.dist`**: Berkas template konfigurasi bawaan developer (*distribution file*).
* **`dvwa/config/config.inc.php`**: Berkas konfigurasi aktif yang dibaca oleh aplikasi web DVWA.

---

### E. Penyesuaian Hak Kepemilikan Berkas Web Server
```bash
sudo chown -R www-data:www-data /var/www/html/dvwa
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`chown`** (*Change Owner*): Perintah Linux untuk mengubah kepemilikan pengguna (*user*) dan grup (*group*) berkas/folder.
* **`-R`** (*Recursive flag*): Menerapkan perubahan kepemilikan ke seluruh subdirektori dan file di dalamnya.
* **`www-data:www-data`**: Pengguna sistem (`user:group`) yang menjalankan proses web server Apache. Diperlukan agar fitur upload dan penulisan database DVWA tidak terhalang galat *Permission Denied*.
* **`/var/www/html/dvwa`**: Jalur direktori target.

---

### F. Penyesuaian Izin Hak Akses Berkas (Permissions)
```bash
sudo chmod -R 755 /var/www/html/dvwa
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`chmod`** (*Change Mode*): Perintah Linux untuk memodifikasi hak izin akses (*read, write, execute*).
* **`-R`** (*Recursive flag*): Menerapkan aturan izin akses ke seluruh pohon folder dan file di bawahnya.
* **`755`** (*Oktal Izin Akses*):
  * Angka `7` (Owner `www-data`): Memiliki hak penuh **Read (4) + Write (2) + Execute (1)**.
  * Angka `5` (Group `www-data`): Memiliki hak **Read (4) + Execute (1)**.
  * Angka `5` (Others/Pengguna lain): Memiliki hak **Read (4) + Execute (1)**.
* **`/var/www/html/dvwa`**: Direktori target.

---

### G. Inisialisasi Basis Data MariaDB via CLI Klien
```bash
sudo mysql -u root
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`mysql`**: Biner klien baris perintah untuk mengelola database MariaDB/MySQL.
* **`-u`** (*User flag*): Parameter penunjuk nama akun database.
* **`root`**: Nama akun pengguna administrator tertinggi sistem database.

#### Kueri SQL Internal yang Dijalankan:
```sql
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
* **`CREATE DATABASE dvwa;`**: Membuat wadah skema basis data baru bernama `dvwa`.
* **`CREATE USER 'dvwa'@'localhost'`**: Membuat entitas pengguna database bernama `dvwa` yang dibatasi koneksinya **hanya dari mesin lokal (`localhost`)**.
* **`IDENTIFIED BY 'p@ssw0rd';`**: Menetapkan kata sandi autentikasi pengguna `dvwa` (nilai ini disinkronkan ke `config.inc.php`).
* **`GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';`**: Memberikan seluruh hak operasional manipulasi tabel (SELECT, INSERT, UPDATE, DELETE, CREATE, DROP) khusus pada skema database `dvwa`.
* **`FLUSH PRIVILEGES;`**: Memaksa server database memuat ulang tabel hak akses (*grant tables*) ke memori seketika.
* **`EXIT;`**: Menutup sesi klien SQL dan kembali ke shell Linux.

---

### H. Restart Web Server Apache
```bash
sudo systemctl restart apache2
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`systemctl`** (*Systemd Control*): Utilitas pengelola daemon Linux.
* **`restart`**: Menghentikan dan menyalakan kembali layanan Apache.
* **`apache2`**: Nama unit daemon web server Apache.

---

## 4. BEDAH MENDALAM ENCODING URL & KARAKTER HEKSADESIMAL

Dalam protokol web HTTP (RFC 3986), karakter tertentu di dalam URI tidak boleh dikirim dalam bentuk karakter mentah karena bertabrakan dengan karakter kendali protokol (seperti spasi, tanda tanya `?`, garis miring `/`, atau tanda petik `'`). Karakter-karakter tersebut harus diubah menjadi **Percent-Encoding (URL Encoding)**.

Format URL Encoding adalah tanda persen (`%`) yang diikuti oleh **dua digit heksadesimal (basis 16)** yang merepresentasikan nilai byte karakter tersebut pada **Tabel ASCII (American Standard Code for Information Interchange)**.

### A. Mengapa Spasi Ditulis `%20`? Kenapa Angka 20?
* Karakter **Spasi (*Space*)** memiliki nilai nomor urut desimal ASCII **`32`**.
* Konversi desimal `32` ke sistem bilangan heksadesimal (basis 16):
  $$32 = (\mathbf{2} \times 16^1) + (\mathbf{0} \times 16^0) = \mathbf{20_{16}}$$
* Oleh karena itu, representasi URL Encoding untuk spasi ditulis secara matematis sebagai **`%20`**.

### B. Mengapa Tanda Petik Tunggal (`'`) Ditulis `%27`? Kenapa Angka 27?
* Karakter **Kutip Tunggal (*Single Quote / Apostrophe*)** memiliki nilai nomor urut desimal ASCII **`39`**.
* Konversi desimal `39` ke sistem bilangan heksadesimal (basis 16):
  $$39 = (\mathbf{2} \times 16^1) + (\mathbf{7} \times 16^0) = \mathbf{27_{16}}$$
* Oleh karena itu, representasi URL Encoding untuk tanda petik tunggal ditulis secara matematis sebagai **`%27`**.

### C. Mengapa Ada Tanda Plus (`+`) untuk Spasi?
* Berdasarkan standar pengiriman formulir web HTML (*MIME Type: `application/x-www-form-urlencoded`*), ketika pengguna mengetik spasi pada formulir pencarian (seperti input User ID di DVWA) dan mengirimkannya via metode HTTP GET, peramban secara otomatis mengonversi spasi menjadi tanda tambah (**`+`**) sebelum dikirim ke jaringan.
* Inilah sebabnya mengapa regex PCRE kita wajib menangani spasi mentah (`\s+`), tanda tambah (`\+`), dan persen dua puluh (`%20`).

### D. Tabel Karakter URL Encoding Penting dalam Web Exploitation

| Karakter Asli | Nama Karakter | Nilai Desimal ASCII | Nilai Heksadesimal | Format URL Encoding | Peran dalam Serangan Web |
|---|---|---|---|---|---|
| *(spasi)* | Space | 32 | `0x20` | **`%20`** atau **`+`** | Pemisah antar kata kunci SQL (`OR`, `UNION`, `SELECT`). |
| `'` | Single Quote | 39 | `0x27` | **`%27`** | Memutus batasan string query SQL pada serangan SQL Injection. |
| `"` | Double Quote | 34 | `0x22` | **`%22`** | Memutus atribut tag HTML pada serangan XSS. |
| `#` | Hash / Sharp | 35 | `0x23` | **`%23`** | Inline comment MySQL (mematikan sisa query di belakang payload). |
| `-` | Dash / Hyphen | 45 | `0x2D` | **`%2D`** | Komentar ganda SQL (`-- `) untuk mematikan sisa query. |
| `=` | Equals | 61 | `0x3D` | **`%3D`** | Komparasi kesetaraan logika boolean SQL (`1=1`, `'a'='a'`). |
| `<` | Less Than | 60 | `0x3C` | **`%3C`** | Membuka tag HTML/JavaScript pada serangan XSS (`<script>`). |
| `>` | Greater Than | 62 | `0x3E` | **`%3E`** | Menutup tag HTML/JavaScript pada serangan XSS (`>`). |
| `/` | Forward Slash | 47 | `0x2F` | **`%2F`** | Penutup tag HTML (`</script>`) dan direktori traversal (`../`). |
| `\` | Backslash | 92 | `0x5C` | **`%5C`** | Karakter escape string. |
| `;` | Semicolon | 59 | `0x3B` | **`%3B`** | Query stacking SQL dan pemisah perintah Command Injection. |
| `%` | Percent | 37 | `0x25` | **`%25`** | Penanda awal encoding atau teknik *Double Encoding* (`%2527`). |
| `\0` | Null Byte | 0 | `0x00` | **`%00`** | Teknik terminasi string untuk membypass filter ekstensi file di PHP lama. |

---

## 5. BEDAH MENDALAM SINTAKS REGEX PCRE

Keyword **`pcre`** pada Suricata menggunakan mesin **Perl-Compatible Regular Expressions**. Pola regex ditulis di dalam pembatas tanda kutip dan garis miring:
$$\mathbf{pcre:"/}\text{pola\_ekspresi\_reguler}\mathbf{/}\text{modifiers}\mathbf{";}$$

### A. Analisis Regex SQLi: `pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"`

```text
  /  ( %27 | \' )  ( \s+ | \+ | %20 )  or  ( \s+ | \+ | %20 )  /  i
 ─── ────────────  ──────────────────  ──  ────────────────── ─── ───
  │        │               │            │           │          │    │
 Delim  Group 1         Group 2       Literal    Group 3     Delim Flag
```

1. **`//` (Delimiters):** Garis miring di awal dan di akhir adalah pembungkus pola regex standar Perl.
2. **`(%27|\')` (Group 1 - Deteksi Kutip Pembuka):**
   * `(...)`: Tanda kurung membentuk *capturing group*.
   * `%27`: Mencocokkan string literal persen dua puluh tujuh (bentuk URL-encoded kutip tunggal).
   * `|` (*Alternation OR*): Operator logika ATAU. Pola cocok jika menemukan sisi kiri ATAU sisi kanan.
   * `\'`: Karakter kutip tunggal literal. Karena tanda kutip merupakan karakter khusus dalam penulisan string, karakter ini diawali tanda garis miring terbalik (*escape backslash* `\`) agar dibaca sebagai karakter kutip murni.
3. **`(\s+|\+|%20)` (Group 2 & Group 3 - Deteksi Pemisah Spasi):**
   * `\s`: Metakarakter yang mencocokkan sembarang karakter spasi putih (*whitespace*), mencakup spasi biasa (`0x20`), tab (`\t`), newline (`\n`), dan carriage return (`\r`).
   * `+` (*Quantifier One-or-More*): Mengharuskan token sebelumnya muncul **minimal 1 kali atau lebih banyak secara berurutan** (misal 1 spasi, 2 spasi, atau 5 spasi tetap cocok).
   * `\+`: Mencocokkan tanda tambah literal (`+`). Karakter plus harus di-escape (`\+`) karena jika berdiri sendiri tanpa backslash, simbol `+` dianggap sebagai quantifier regex.
   * `%20`: Mencocokkan bentuk URL-encoded dari spasi.
4. **`or` (Literal SQL Operator):** Mencocokkan kata kunci logika boolean SQL "or".
5. **`/i` (Case-Insensitive Modifier):** Menjadikan pencocokan kebal terhadap variasi huruf besar dan huruf kecil. Kata `or`, `OR`, `Or`, maupun `oR` akan cocok secara identik.

---

### B. Analisis Regex XSS: `pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui"`

```text
  / < (script|...|source) [^>]+ (src|onerror|onload) \s* = / Ui
 ── ─ ─────────────────── ───── ──────────────────── ─── ─ ─ ──
  │ │          │            │            │            │  │ │  │
  D <       Tag Names    Not '>'   Event Handlers   Space= D Flags
```

1. **`<`**: Mencocokkan karakter kurung siku buka pembuka tag HTML.
2. **`(script|img|svg|iframe|video|source)`**: Alternation yang mencocokkan salah satu nama tag HTML yang sering digunakan penyerang untuk menyuntikkan skrip berbahaya. Mencakup tag multimedia `<video>` dan `<source>` yang dipakai pada video dosen `XSS.mkv`.
3. **`[^>]+` (Negated Character Class):**
   * `[...]`: *Character class* (kumpulan karakter yang diizinkan).
   * `^>`: Tanda caret (`^`) di awal kelas karakter berarti **negasi (bukan)**. Pola ini mencocokkan sembarang karakter apa pun **asalkan bukan karakter kurung siku tutup `>`**.
   * `+`: Satu atau lebih karakter.
   * *Urgensi teknis:* Ini memastikan atribut `onerror=` masih berada **di dalam tag yang sama**, dan mencegah regex mencocokkan tag terpisah yang berbeda.
4. **`(src|onerror|onload)`**: Mencocokkan atribut sumber data atau pengendali kejadian (*event handler*) yang mengeksekusi JavaScript secara otomatis saat gambar/video gagal dimuat.
5. **`\s*=`**: Mencocokkan tanda sama dengan (`=`) yang didahului oleh nol atau lebih karakter spasi (`\s*`).
6. **`/Ui` (Modifiers):**
   * **`U`** (*Ungreedy / URI matching*): Pada Suricata, flag `U` memberi instruksi agar pencocokan regex dievaluasi terhadap buffer normalized URI (`http.uri`).
   * **`i`** (*Case-Insensitive*): Kebal terhadap huruf besar/kecil (misal `<IMG SRC=x ONERROR=...>`).

---

## 6. BEDAH MENDALAM TCP FLAGS & MASKING BIT ECN

Header protokol TCP (RFC 793) memiliki field kontrol ukuran 8-bit yang berisi bendera kendali koneksi (*Control Flags*):

```text
  Bit 7    Bit 6    Bit 5    Bit 4    Bit 3    Bit 2    Bit 1    Bit 0
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│  CWR   │  ECE   │  URG   │  ACK   │  PSH   │  RST   │  SYN   │  FIN   │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┴────────┘
  Bit 1    Bit 2
 (Snort/Suricata ECN Mask: 1, 2)
```

### A. Arti Masing-Masing Bendera TCP
1. **SYN (Synchronize - Bit 1):** Menginisiasi jabat tangan koneksi baru (*Three-Way Handshake*).
2. **ACK (Acknowledge - Bit 4):** Mengonfirmasi penerimaan paket data sebelumnya.
3. **FIN (Finish - Bit 0):** Meminta pemutusan koneksi secara normal.
4. **RST (Reset - Bit 2):** Memutus koneksi secara paksa/seketika.
5. **PSH (Push - Bit 3):** Meminta aplikasi segera memproses data di buffer tanpa menunggu antrean penuh.
6. **URG (Urgent - Bit 5):** Menandai data mendesak yang diprioritaskan.
7. **ECE (ECN-Echo - Bit 6):** Notifikasi kemacetan jaringan (RFC 3168).
8. **CWR (Congestion Window Reduced - Bit 7):** Konfirmasi bahwa jendela kemacetan telah diperkecil.

### B. Mengapa Sintaksnya Tertulis `flags:S,12;`? Kenapa Angka 12?
Format resmi kata kunci `flags` pada Snort dan Suricata adalah:
$$\mathbf{flags:[check\_flags],[mask\_flags];}$$
* **`check_flags` (Karakter sebelum koma):** Bendera yang **WAJIB AKTIF (bernilai 1)**. Huruf `S` berarti bendera **SYN** harus aktif.
* **`mask_flags` (Karakter setelah koma):** Bendera yang **DIABAIKAN (*MASK OUT*)**.
* **Angka `12`:** Merepresentasikan **Bit ECN 1 (CWR)** dan **Bit ECN 2 (ECE)**.
* **Alasan Teknis untuk Ujian:** Sistem operasi modern (Windows 11, Linux kernel baru) dan perangkat router jaringan sering mengaktifkan fitur ECN secara otomatis pada paket SYN. Jika kita hanya menulis `flags:S;` secara kaku tanpa masking `,12`, maka ketika ada paket SYN yang membawa bit ECN aktif (`SYN + ECE`), Suricata akan menolak paket tersebut dan alert tidak akan berbunyi. Masking `,12` menjamin rule tetap memicu alert pada seluruh paket SYN tanpa terganggu oleh bit kemacetan jaringan.

---

## 7. BEDAH MENDALAM STICKY BUFFER & ENGINE PREPROCESSOR SURICATA

Pada Suricata versi modern, pencarian muatan paket tidak dilakukan secara acak pada seluruh biner paket (*raw packet payload*), melainkan menggunakan konsep **Sticky Buffer**.

### A. Apa itu Sticky Buffer?
Sticky buffer adalah pointer area memori terisolasi yang dihasilkan oleh mesin prapemrosesan (*preprocessor engine*) Suricata setelah merekonstruksi aliran stream TCP dan mengurai struktur protokol HTTP.

Ketika kata kunci `http.uri;` ditulis, seluruh parameter pencarian di belakangnya (`content`, `pcre`, `nocase`) secara otomatis "menempel" (*sticky*) dan hanya memeriksa area memori URI tersebut.

### B. Mengapa Menggunakan `http.uri` Bukan Seluruh Paket?
1. **Akselerasi Kecepatan Inspeksi (Hardware Matching):** Menghindari engine memindai ribuan byte paket gambar, CSS, atau muatan biner yang tidak relevan. Pencarian dibatasi hanya pada beberapa puluh karakter string URL.
2. **Ketahanan Terhadap Teknik Evasion (Anti-Bypass):** Preprocessor Suricata secara otomatis melakukan normalisasi terhadap URL:
   * Mengubah representasi heksadesimal ganda menjadi karakter baku.
   * Menghapus karakter traversal direktori palsu (`/vulnerabilities/./sqli/` menjadi `/vulnerabilities/sqli/`).
   * Menyelaraskan encoding sebelum dievaluasi oleh parameter `content`.

---

## 8. BEDAH MENDALAM MESIN LAJU TRAFIK (THRESHOLDING)

Format dasar:
$$\mathbf{threshold:type\ [type], track\ [by\_src|by\_dst], count\ [N], seconds\ [T];}$$

### A. Tiga Tipe Ambang Batas (`type`)
1. **`type threshold`:**
   * Memicu alert **setiap kali** hitungan ke-$N$ tercapai dalam rentang waktu $T$ detik.
   * *Karakteristik:* Jika ada 300 paket dan count diatur 100, alert akan berbunyi pada paket ke-100, ke-200, dan ke-300.
2. **`type limit`:**
   * Memicu alert **paling banyak** $N$ kali dalam rentang waktu $T$ detik. Kejadian selanjutnya diabaikan sampai waktu $T$ berakhir.
3. **`type both` (Yang Kita Gunakan untuk DoS):**
   * Menggabungkan kedua logika: memicu alert **tepat 1 kali saja** ketika hitungan $N$ tercapai dalam rentang $T$ detik, kemudian **meredam (*suppress*) seluruh alert lanjutan** selama sisa detik tersebut.
   * *Urgensi:* Mencegah serangan DoS membanjiri harddisk server dengan jutaan baris log dalam hitungan detik (*log exhaustion*).

### B. Pelacakan (`track`)
* **`track by_src`**: Ambang batas dihitung berdasarkan **alamat IP sumber (penyerang)**. Setiap penyerang memiliki kuota hitungannya masing-masing.
* **`track by_dst`**: Ambang batas dihitung berdasarkan **alamat IP tujuan (server korban)**, tanpa memedulikan siapa pengirimnya (berguna untuk mendeteksi serangan *Distributed Denial of Service / DDoS* dari ribuan botnet).

---

## 9. BEDAH SELURUH BARIS RULES PRAKTIKUM

Berikut adalah bedah mandiri lengkap untuk **setiap baris rule**. Seluruh parameter dibedah tuntas pada masing-masing rule tanpa ada yang dilewati.

---

### Rule A: SYN Flood (Bab V Modul - sid:1000001)
```text
alert tcp any any -> $HOME_NET 80 (msg:"POSSIBLE SYN FLOOD DETECTED"; flags:S,12; threshold:type threshold, track by_src, count 100, seconds 5; classtype:attempted-dos; sid:1000001; rev:1;)
```
* **`alert`**: Aksi Mode IDS. Jika paket cocok, catat peringatan ke berkas log (`fast.log`), paket asli tetap dilewatkan ke tujuan.
* **`tcp`**: Protokol transport layer 4 yang diperiksa (Transmission Control Protocol).
* **`any` (Source IP)**: Alamat IP pengirim penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim penyerang dari nomor port berapa saja.
* **`->`** (*Direction Operator*): Arah aliran lalu lintas satu arah (dari pengirim penyerang menuju server penerima).
* **`$HOME_NET`**: Variabel alamat IP tujuan yang mewakili server korban yang dilindungi (didefinisikan di `suricata.yaml`, misal `192.168.2.3/32`).
* **`80`**: Nomor port tujuan yang dilindungi (port layanan web HTTP Apache).
* **`msg:"POSSIBLE SYN FLOOD DETECTED"`**: Teks pesan peringatan deskriptif yang dicetak ke file log saat serangan terdeteksi.
* **`flags:S,12;`**:
  * `S`: Bendera TCP **SYN** (*Synchronize*) wajib aktif bernilai 1.
  * `,12`: Mengabaikan (*masking*) bit ECN 1 (CWR) dan bit ECN 2 (ECE) agar paket SYN dari OS modern yang mendukung ECN tetap terdeteksi.
* **`threshold:type threshold, track by_src, count 100, seconds 5;`**:
  * `type threshold`: Mengeluarkan alert setiap kali hitungan batas tercapai.
  * `track by_src`: Perhitungan ambang batas dihitung berdasarkan satu alamat IP pengirim tunggal.
  * `count 100, seconds 5`: Ambang batas: memicu alert jika penyerang mengirimkan minimal 100 paket SYN dalam kurun waktu 5 detik.
* **`classtype:attempted-dos;`**: Klasifikasi kategori percobaan penolakan layanan (otomatis dipetakan oleh Suricata ke tingkat keparahan **Priority 2 / Medium**).
* **`sid:1000001;`** (*Signature ID*): Nomor identitas pengenal unik rule (nomor $\ge 1.000.000$ dicadangkan khusus untuk rule lokal buatan pengguna).
* **`rev:1;`** (*Revision*): Nomor versi perubahan rule (revisi ke-1).

---

### Rule B: ICMP Burst (Bab V Modul - sid:1000002)
```text
alert icmp any any -> $HOME_NET any (msg:"ICMP ECHO BURST DETECTED"; itype:8; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000002; rev:3;)
```
* **`alert`**: Aksi Mode IDS. Catat kejadian ke log, paket tetap melintas.
* **`icmp`**: Protokol kendali jaringan layer 3 *Internet Control Message Protocol* (protokol pengujian ping).
* **`any` (Source IP)**: Alamat IP pengirim dari mana saja.
* **`any` (Source Port)**: Protokol ICMP tidak memiliki nomor port, sehingga diisi `any`.
* **`->`**: Arah lalu lintas paket masuk.
* **`$HOME_NET`**: Alamat IP server target yang dilindungi.
* **`any` (Destination Port)**: Port tujuan bernilai `any` karena ICMP bekerja di Layer 3 tanpa konsep nomor port Layer 4.
* **`msg:"ICMP ECHO BURST DETECTED"`**: Teks pesan peringatan yang dicetak ke `fast.log`.
* **`itype:8;`** (*ICMP Type 8*): Parameter filter tipe paket ICMP. Angka 8 adalah kode resmi untuk **Echo Request** (permintaan ping). Parameter ini penting agar paket balasan *Echo Reply* (Type 0) dari server tidak ikut memicu alert.
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**:
  * `type threshold`: Mengeluarkan alert setiap kelipatan hitungan tercapai.
  * `track by_src`: Menghitung laju paket berdasarkan IP pengirim tunggal.
  * `count 8, seconds 5`: Memicu alert jika penyerang mengirimkan lebih dari 8 paket ping dalam rentang 5 detik.
* **`classtype:attempted-dos;`**: Klasifikasi serangan penolakan layanan (Priority 2).
* **`sid:1000002;`**: Signature ID 1000002.
* **`rev:3;`**: Nomor revisi ke-3.

---

### Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)
```text
alert udp any any -> $HOME_NET 53 (msg:"UDP BURST TO DNS PORT DETECTED"; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000003; rev:1;)
```
* **`alert`**: Aksi Mode IDS. Catat kejadian ke log tanpa membuang paket.
* **`udp`**: Protokol transport layer 4 *User Datagram Protocol* (tanpa koneksi / *connectionless*).
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim acak penyerang.
* **`->`**: Arah lalu lintas paket masuk.
* **`$HOME_NET`**: Alamat IP server tujuan yang dilindungi.
* **`53`**: Nomor port tujuan DNS server (*Domain Name System*).
* **`msg:"UDP BURST TO DNS PORT DETECTED"`**: Teks pesan peringatan di file log.
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**:
  * `type threshold`: Memicu alert setiap ambang batas kelipatan tercapai.
  * `track by_src`: Menghitung laju paket berdasarkan IP pengirim tunggal.
  * `count 8, seconds 5`: Memicu alert jika penyerang mengirim lebih dari 8 paket UDP ke port 53 dalam kurun waktu 5 detik (indikasi *DNS Flood/Amplification*).
* **`classtype:attempted-dos;`**: Kategori penolakan layanan (Priority 2).
* **`sid:1000003;`**: Signature ID 1000003.
* **`rev:1;`**: Nomor revisi ke-1.

---

### Rule 1: SQL Injection Tautology Bypass (sid:1000021)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi SQL Injection (Tautology Bypass)"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:2;)
```
* **`alert`**: Aksi Mode IDS. Catat bukti serangan ke log, izinkan paket lewat ke web server DVWA.
* **`http`**: Parser protokol lapisan aplikasi HTTP Suricata yang mampu mengurai komponen request web.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim peramban penyerang yang bersifat dinamis.
* **`->`**: Arah lalu lintas paket satu arah dari klien penyerang ke server.
* **`$HOME_NET`**: Alamat IP server web korban yang dilindungi (`192.168.2.3/32`).
* **`80`**: Port layanan web server Apache target.
* **`msg:"[DVWA ATTACK] Terdeteksi Eksploitasi SQL Injection (Tautology Bypass)"`**: Pesan peringatan yang dicetak ke `fast.log`.
* **`flow:established,to_server;`**:
  * `established`: Memastikan koneksi TCP telah menyelesaikan Three-Way Handshake secara sempurna.
  * `to_server`: Hanya memeriksa paket yang mengalir dari arah klien penyerang menuju server korban, mengabaikan paket balasan server.
* **`http.uri;`**: *Sticky buffer*. Menginstruksikan Suricata agar pencarian string hanya dilakukan pada pointer memori baris URL path dan parameter query.
* **`content:"/vulnerabilities/sqli/";`**: Pola teks string yang wajib ada, memastikan request ditujukan ke modul rentan SQLi DVWA.
* **`nocase;`**: Mengabaikan kapitalisasi huruf pada parameter `content` sebelumnya.
* **`pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i";`**:
  * `(%27|\')`: Menangkap karakter kutip tunggal URL-encoded (`%27`) atau kutip tunggal asli (`'`).
  * `(\s+|\+|%20)`: Menangkap pemisah spasi putih (`\s+`), tanda tambah formulir browser (`\+`), atau encoding spasi (`%20`).
  * `or`: Kata kunci operator logika SQL boolean.
  * `/i`: Flag regex kebal terhadap huruf besar/kecil (`OR`, `or`, `Or`).
* **`classtype:web-application-attack;`**: Kategori serangan aplikasi web (otomatis memetakan ke tingkat keparahan **Priority 1 / High**).
* **`sid:1000021;`**: Signature ID unik 1000021.
* **`rev:2;`**: Nomor revisi ke-2 (revisi perbaikan penanganan tanda `+`).

---

### Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi Reflected XSS (Event Handler Bypass)"; flow:established,to_server; http.uri; pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui"; classtype:web-application-attack; sid:1000022; rev:2;)
```
* **`alert`**: Aksi Mode IDS. Catat bukti kejadian ke log, izinkan paket asli tetap melintas ke peramban tanpa diputus.
* **`http`**: Protokol aplikasi web HTTP yang diurai oleh parser internal Suricata.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port klien penyerang dari nomor port acak mana saja.
* **`->`** (*Direction Operator*): Arah aliran paket satu arah dari klien menuju server korban.
* **`$HOME_NET`**: Alamat IP server web korban yang dilindungi (`192.168.2.3/32`).
* **`80`**: Nomor port layanan web HTTP Apache tempat DVWA berjalan.
* **`msg:"[DVWA ATTACK] Terdeteksi Eksploitasi Reflected XSS (Event Handler Bypass)"`**: Pesan peringatan alert yang dicetak ke `fast.log`.
* **`flow:established,to_server;`**:
  * `established`: Memastikan sesi koneksi TCP telah terjalin sah melalui *Three-Way Handshake*.
  * `to_server`: Memeriksa hanya paket permintaan yang mengalir dari arah klien penyerang menuju server korban (mengabaikan respon server).
* **`http.uri;`**: *Sticky buffer*. Mengarahkan pencarian payload hanya pada baris URL request.
* **`pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui";`**:
  * `<`: Karakter kurung siku buka pembuka tag HTML.
  * `(script|img|svg|iframe|video|source)`: Daftar tag HTML yang umum disalahgunakan untuk eksekusi skrip (termasuk tag `<video>` dan `<source>` pada video dosen `XSS.mkv`).
  * `[^>]+`: Negated character class. Menangkap sembarang karakter apa pun asalkan bukan kurung siku tutup `>`, memastikan atribut masih berada di dalam tag yang sama.
  * `(src|onerror|onload)`: Daftar atribut eksekusi script otomatis peramban (*event handler*).
  * `\s*=`: Tanda sama dengan yang didahului nol atau lebih karakter spasi.
  * `/Ui`: Modifier `U` (evaluasi pada buffer normalized URI) dan `i` (case-insensitive).
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000022;`**: Signature ID 1000022.
* **`rev:2;`**: Nomor revisi ke-2.

---

### Rule 3: CSRF Unauthorized Password Change (sid:1000023)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Upaya Eksploitasi CSRF Ganti Password"; flow:established,to_server; http.uri; content:"/vulnerabilities/csrf/"; nocase; content:"password_new="; nocase; classtype:web-application-attack; sid:1000023; rev:1;)
```
* **`alert`**: Aksi Mode IDS. Catat bukti kejadian ke log, izinkan paket tetap melintas ke tujuan.
* **`http`**: Protokol lapisan aplikasi web HTTP.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim klien penyerang yang bersifat dinamis.
* **`->`** (*Direction Operator*): Arah paket satu arah dari klien penyerang menuju server penerima.
* **`$HOME_NET`**: Alamat IP server web korban yang dilindungi (`192.168.2.3/32`).
* **`80`**: Nomor port layanan web HTTP Apache tempat DVWA berjalan.
* **`msg:"[DVWA ATTACK] Terdeteksi Upaya Eksploitasi CSRF Ganti Password"`**: Pesan alert yang dicetak ke `fast.log`.
* **`flow:established,to_server;`**:
  * `established`: Memastikan sesi TCP telah terbentuk sempurna.
  * `to_server`: Memeriksa hanya paket yang mengalir menuju server (request klien).
* **`http.uri;`**: *Sticky buffer*. Mengunci area pencarian string hanya pada baris URL request.
* **`content:"/vulnerabilities/csrf/";`**: String pencocokan jalur direktori modul CSRF DVWA.
* **`nocase;`**: Mengabaikan kapitalisasi huruf pada parameter content `/vulnerabilities/csrf/`.
* **`content:"password_new=";`**: String pencocokan kedua yang mendeteksi parameter pergantian kata sandi pada URL.
* **`nocase;`**: Mengabaikan kapitalisasi huruf pada parameter content `password_new=`.
* **`classtype:web-application-attack;`**: Kategori serangan aplikasi web (Priority 1).
* **`sid:1000023;`**: Signature ID 1000023.
* **`rev:1;`**: Nomor revisi ke-1.

---

### Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)
```text
alert tcp any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Serangan DoS TCP SYN Flood ke Port Layanan DVWA"; flags:S; threshold: type both, track by_src, count 15, seconds 3; classtype:denial-of-service; sid:1000024; rev:3;)
```
* **`alert`**: Aksi Mode IDS. Catat peringatan lonjakan paket ke berkas log tanpa membuang paket.
* **`tcp`**: Protokol transport layer 4 TCP (Transmission Control Protocol).
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Nomor port pengirim penyerang dari mana saja.
* **`->`** (*Direction Operator*): Arah paket satu arah dari penyerang menuju server korban.
* **`$HOME_NET`**: Alamat IP server target yang dilindungi (`192.168.2.3/32`).
* **`80`**: Nomor port tujuan layanan web HTTP Apache target.
* **`msg:"[DVWA ATTACK] Terdeteksi Serangan DoS TCP SYN Flood ke Port Layanan DVWA"`**: Pesan peringatan yang dicetak ke file log saat serangan terdeteksi.
* **`threshold: type both, track by_src, count 15, seconds 3;`**:
  * `type both`: Mengeluarkan alert tepat satu kali ketika batas 15 paket tercapai, lalu **menahan (*suppress*)** alert berulang selama jendela waktu 3 detik agar harddisk server tidak penuh akibat banjir log.
  * `track by_src`: Menghitung laju paket berdasarkan satu alamat IP penyerang tunggal.
  * `count 15, seconds 3`: Ambang batas sensitif: memicu alert jika penyerang mengirimkan minimal 15 paket SYN dalam kurun waktu 3 detik.
* **`classtype:denial-of-service;`**: Klasifikasi kategori penolakan layanan (otomatis dipetakan Suricata ke **Priority 2 / Medium**).
* **`sid:1000024;`**: Signature ID 1000024.
* **`rev:3;`**: Nomor revisi ke-3.

---

### Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)
```text
drop http any any -> $HOME_NET 80 (msg:"[DVWA IPS BLOCK] SQL Injection Dropped"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:5;)
```
* **`drop`**: **Aksi Pencegahan Mode IPS**. Memerintahkan kernel Linux melalui antrean NFQUEUE untuk seketika memusnahkan (*drop/discard*) paket serangan di memori kernel. Paket tidak pernah mencapai port 80 web server Apache, peramban penyerang menampilkan galat *Connection Timed Out*, dan basis data pengguna batal bocor.
* **`http`**: Protokol aplikasi web HTTP.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim klien penyerang dari mana saja.
* **`->`** (*Direction Operator*): Arah aliran paket satu arah dari klien penyerang menuju server.
* **`$HOME_NET`**: Alamat IP server web korban yang dilindungi (`192.168.2.3/32`).
* **`80`**: Port layanan web server Apache target.
* **`msg:"[DVWA IPS BLOCK] SQL Injection Dropped"`**: Teks pesan pemblokiran yang dicatat ke `fast.log` dengan label `[Drop]`.
* **`flow:established,to_server;`**:
  * `established`: Memastikan sesi koneksi TCP telah terjalin sah.
  * `to_server`: Memeriksa hanya paket yang mengalir menuju server.
* **`http.uri;`**: *Sticky buffer*. Mengarahkan pencarian payload hanya pada pointer memori baris URL path dan parameter query.
* **`content:"/vulnerabilities/sqli/";`**: Pencocokan string direktori modul SQLi DVWA.
* **`nocase;`**: Case-insensitive untuk parameter content.
* **`pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i";`**: Regex penangkap pola tautologi kutip satu (`'` / `%27`), pemisah spasi/tanda tambah, dan kata kunci `or`.
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000021;`**: Signature ID 1000021.
* **`rev:5;`**: Nomor revisi ke-5 (revisi peningkatan ke aksi drop IPS).

---

## 10. KONSEPTUAL ARSITEKTUR: MODE IDS VS MODE IPS

| Parameter Evaluasi | Mode IDS (Intrusion Detection System) | Mode IPS (Intrusion Prevention System) |
|---|---|---|
| **Sifat Pertahanan** | **Pasif & Reaktif** (Mendeteksi dan mencatat) | **Aktif & Preventif** (Mencegat dan memblokir) |
| **Kata Aksi Rule** | `alert` | `drop` atau `reject` |
| **Mekanisme Jaringan** | *Out-of-band / Sniffing* via driver `AF_PACKET` | *Inline / In-path* via driver antrean kernel `NFQUEUE` |
| **Perintah Eksekusi** | `suricata --af-packet=enp0s8` atau `systemctl start suricata` | `iptables ... -j NFQUEUE` lalu `suricata -q 0` |
| **Dampak ke Penyerang** | Serangan sukses dieksekusi, database bocor | Serangan gagal total, koneksi diputus / *Timed Out* |
| **Format Pencatatan Log** | Ditandai dengan `[**]` di `fast.log` | Ditandai dengan label `[Drop]` di `fast.log` |
| **Risiko Operasional** | Nol risiko terhadap kelancaran layanan sah | Berisiko memblokir pengguna sah jika terjadi *False Positive* |
| **Beban Latensi Jaringan** | 0 milidetik (hanya membaca salinan paket) | Ada sedikit latensi mikrodetik karena paket ditahan di antrean kernel |

---

## 11. FAQ UJIAN LISAN: MENJALANKAN SURICATA MODE IDS VS MEMANTAU LOG

### Pertanyaan Jebakan Dosen:
> *"Bagaimana cara menjalankan Suricata dalam mode IDS? Apakah perintahnya `sudo tail -f /var/log/suricata/fast.log`?"*

**JAWABAN TEGAS: BUKAN.**  
`sudo tail -f /var/log/suricata/fast.log` **BUKAN** perintah untuk menjalankan Suricata. Perintah `tail -f` hanyalah program pembaca berkas teks untuk melihat isi buku catatan log secara real-time. Jika mesin Suricata mati, perintah `tail -f` tetap terbuka di layar, namun kosong dan tidak akan mendeteksi serangan apa pun.

#### Analogi Sederhana:
* **Menjalankan Mesin Suricata (`systemctl start` / `suricata --af-packet`)** = Menyalakan kamera CCTV dan mengarahkan lensanya ke jalan raya.
* **Menjalankan `tail -f fast.log`** = Menatap layar monitor ruang sekuriti untuk membaca laporan tertulis yang dicatat kamera CCTV.

---

### Empat Cara Resmi Menjalankan Suricata dalam Mode IDS (Beserta Bedah Kata per Kata)

#### 1. Mode IDS Berjalan di Latar Belakang (Background Service Daemon)
```bash
sudo systemctl start suricata
```
* **`sudo`** (*SuperUser DO*): Menjalankan perintah dengan hak akses root tertinggi Linux.
* **`systemctl`** (*Systemd Control*): Utilitas pengelola sistem inisialisasi dan layanan daemon (*systemd*).
* **`start`**: Perintah untuk menyalakan dan menjalankan layanan di latar belakang (*background*). Di balik layar, systemd membaca konfigurasi `af-packet` pada `suricata.yaml` secara otomatis.
* **`suricata`**: Nama unit layanan sistem (`suricata.service`).

#### 2. Mode IDS Langsung di Terminal via `AF_PACKET` (Live Sniffing Modern)
```bash
sudo suricata -c /etc/suricata/suricata.yaml --af-packet=enp0s8 -v
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk mengaktifkan *promiscuous mode* pada antarmuka jaringan.
* **`suricata`**: Biner aplikasi mesin IDS Suricata.
* **`-c`** (*Config file flag*): Menentukan lokasi berkas konfigurasi master.
* **`/etc/suricata/suricata.yaml`**: Jalur absolut file konfigurasi utama Suricata.
* **`--af-packet=enp0s8`**: Parameter saklar driver tangkap paket berkecepatan tinggi (*Linux AF_PACKET socket*) yang menginstruksikan Suricata menyadap lalu lintas jaringan secara pasif pada kartu jaringan **`enp0s8`**.
* **`-v`** (*Verbose flag*): Menampilkan proses inisialisasi memori, pengenalan thread, dan pembacaan rules langsung ke layar terminal secara mendetail.

#### 3. Mode IDS Langsung di Terminal via `libpcap` (Live Sniffing Klasik)
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i enp0s8 -v
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk membuka soket sniffing mentah.
* **`suricata`**: Biner aplikasi mesin IDS Suricata.
* **`-c`** (*Config file flag*): Penunjuk jalur konfigurasi.
* **`/etc/suricata/suricata.yaml`**: File konfigurasi master Suricata.
* **`-i`** (*Interface flag*): Parameter penentu nama kartu jaringan fisik/virtual yang disadap menggunakan driver standar *libpcap*.
* **`enp0s8`**: Nama kartu jaringan Host-Only VirtualBox yang menjadi jalur serangan antara Kali Linux dan Ubuntu.
* **`-v`** (*Verbose flag*): Menampilkan log diagnostik inisialisasi ke layar terminal.

#### 4. Mode IDS Offline (Membaca Rekaman Paket `.pcap` Forensik)
```bash
sudo suricata -c /etc/suricata/suricata.yaml -r _attack_and_normal.pcap -l /var/log/suricata/
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk menulis hasil log ke direktori sistem.
* **`suricata`**: Biner aplikasi mesin IDS Suricata.
* **`-c`** (*Config file flag*): Penunjuk jalur konfigurasi.
* **`/etc/suricata/suricata.yaml`**: File konfigurasi master Suricata.
* **`-r`** (*Read PCAP flag*): Mengaktifkan mode baca berkas rekaman (*offline replay*). Suricata tidak mendengarkan kartu jaringan, melainkan memproses paket masa lalu di dalam file `.pcap` seolah-olah lewat secara live.
* **`_attack_and_normal.pcap`**: Nama file rekaman paket jaringan yang dianalisis.
* **`-l`** (*Log directory flag*): Menentukan direktori folder tujuan penyimpanan hasil laporan log.
* **`/var/log/suricata/`**: Alamat folder tempat berkas `fast.log` dan `eve.json` hasil analisis disimpan.

---

### Ringkasan Singkat Prosedur di Terminal Saat Live Demo:
1. **Nyalakan mesin IDS-nya** (di Terminal 1):
   * Pakai background service: `sudo systemctl start suricata`
   * *atau* pakai mode langsung CLI: `sudo suricata -c /etc/suricata/suricata.yaml -i enp0s8 -v`
2. **Buka monitor log-nya** (di Terminal 2):
   * Pantau hasil deteksinya dengan: `sudo tail -f /var/log/suricata/fast.log`

---

## 12. PANDUAN LENGKAP FOOTPRINTING & OSINT: SPIDERFOOT V4.0.0

### A. Konsep Dasar Footprinting & Pengintaian OSINT
* **Footprinting:** Tahap awal pengumpulan informasi secara komprehensif mengenai target (jaringan, sistem, perangkat lunak, dan organisasi) sebelum melancarkan serangan siber. Merupakan fase pertama dalam metodologi *Cyber Kill Chain* dan *PTES (Penetration Testing Execution Standard)*.
* **OSINT (Open Source Intelligence):** Pengumpulan data intelijen yang bersumber secara legal dari catatan publik terbuka (DNS, SSL Certificate Transparency, arsip mesin pencari, registri WHOIS, dan rute BGP) tanpa melakukan eksploitasi sistem.
* **Passive vs Active Reconnaissance:**
  * *Passive Recon:* Mengumpulkan data tanpa berinteraksi langsung dengan server sasaran (misal query ke crt.sh atau Shodan). Tidak meninggalkan jejak log di server target.
  * *Active Recon:* Berinteraksi langsung dengan server sasaran (seperti melakukan port scanning TCP dan HTTP banner grabbing). Meninggalkan jejak log di firewall/IDS target.

---

### B. Bedah Perintah Instalasi & Troubleshooting Dependensi Kata per Kata

#### 1. Mengunduh Kode Sumber SpiderFoot
```bash
git clone https://github.com/smicallef/spiderfoot.git
```
* **`git`**: Program sistem pengontrol versi terdistribusi.
* **`clone`**: Perintah untuk mengunduh salinan repositori penuh dari internet ke komputer lokal.
* **`https://github.com/smicallef/spiderfoot.git`**: Alamat repositori resmi framework SpiderFoot yang dikembangkan oleh Steve Micallef.

#### 2. Isolasi Virtual Environment Python
```bash
python -m venv sf-env
```
* **`python`**: Interpreter bahasa pemrograman Python.
* **`-m`** (*Module flag*): Parameter saklar yang memerintahkan Python untuk mengeksekusi sebuah modul pustaka standar sebagai skrip mandiri.
* **`venv`**: Modul pustaka bawaan Python untuk membuat lingkungan virtual (*Virtual Environment*) yang terisolasi dari direktori sistem utama.
* **`sf-env`**: Nama folder lokal tempat pustaka dan biner Python terisolasi disimpan.

#### 3. Aktivasi Virtual Environment
* Di Windows PowerShell:
  ```powershell
  .\sf-env\Scripts\Activate.ps1
  ```
* Di Linux / macOS:
  ```bash
  source sf-env/bin/activate
  ```
* **Fungsi:** Mengubah environment variable `PATH` agar perintah `python` dan `pip` mengarah ke folder lokal `sf-env`, ditandai dengan munculnya prefiks `(sf-env)` di awal baris terminal prompt.

#### 4. Pembaruan Paket Manajer pip
```bash
python -m pip install --upgrade pip
```
* **`python -m pip`**: Menjalankan modul penginstal paket Python (*pip*).
* **`install`**: Subperintah untuk memasang atau memperbarui pustaka.
* **`--upgrade`**: Opsi saklar untuk memaksa pip memperbarui dirinya sendiri ke versi stabil terbaru yang tersedia di repositori PyPI.
* **`pip`**: Nama paket manajer yang diperbarui.

#### 5. Bedah Dua Kendala Teknis (*Troubleshooting*)
* **Error 1 (`ModuleNotFoundError: No module named 'cherrypy'`):**
  * *Penyebab:* Skrip utama `sf.py` pada baris 25 membutuhkan mikroframework web server CherryPy untuk melayani antarmuka Web UI di port 5001. Jika dependensi belum dipasang, program crash seketika.
  * *Solusi:* Memasang paket CherryPy di dalam virtual environment terisolasi.
* **Error 2 (Inkompatibilitas C-API Pustaka Modern pada Python 3.14):**
  * *Penyebab:* Saat mengeksekusi `pip install -r requirements.txt`, terjadi kegagalan kompilasi beruntun:
    1. `lxml < 5`: Gagal kompilasi GCC karena perubahan fungsi internal C-API `_PyLong_AsByteArray`.
    2. `dnspython >= 2.6`: Menghapus fungsi lawas `restore_system_resolver()`, menyebabkan worker SpiderFoot deadlock.
    3. `MarkupSafe 3.x`: Menghapus modul `escape` yang diakses oleh engine template Mako bawaan SpiderFoot.
  * *Solusi Teknis:* Melakukan *dependency pinning* versi stabil yang memiliki pre-compiled wheel biner Windows:
    ```bash
    pip install "lxml>=5.3.0" "markupsafe==2.1.5" "dnspython==2.5.0"
    pip install -r requirements.txt
    ```

#### 6. Menjalankan Server Web GUI SpiderFoot
```bash
python sf.py -l 127.0.0.1:5001
```
* **`python`**: Biner interpreter Python aktif.
* **`sf.py`**: Berkas skrip utama peluncur SpiderFoot (*SpiderFoot Core Script*).
* **`-l`** (*Listen address & port flag*): Parameter untuk menentukan alamat IP pengikatan (*binding host*) dan nomor port web server internal.
* **`127.0.0.1:5001`**: Mengikat layanan web server CherryPy pada alamat loopback lokal `127.0.0.1` pada port **`5001`**. Layanan diakses via browser dengan mengetikkan `http://127.0.0.1:5001/`.

---

### C. Bedah Konfigurasi 3 Filter pada Halaman New Scan

Saat membuat sesi audit baru di antarmuka Web GUI (`New Scan`):
1. **Kolom Identitas Sasaran:**
   * **Scan Name:** `AUDIT-KOMPUTER-UNSOED` (Pengenal nama sesi pemindaian).
   * **Scan Target (Seed):** `komputer.ft.unsoed.ac.id`
     * *Aturan Teknis:* Wajib dimasukkan **hanya nama domain mentah**, tanpa diawali protokol `http://` atau `https://` dan tanpa garis miring di akhir (`/`). Jika menyertakan `http://`, modul pencarian subdomain, WHOIS, dan DNS tidak akan berjalan optimal karena format input dianggap sebagai URL tunggal, bukan domain root.
2. **Filter 1: Tab By Use Case (Opsi: `Footprint`)**
   * Dipilih opsi **Footprint** (*Active Reconnaissance non-passive*).
   * *Fungsi:* Mengaktifkan pemetaan perimeter jaringan, merayapi tautan web (*web spidering*), dan mengidentifikasi perangkat lunak web server target.
3. **Filter 2: Tab By Required Data (Fokus Celah Keamanan)**
   * **Data yang Dicentang (Aktif / Checked):** Tipe data yang berkaitan langsung dengan evaluasi celah keamanan:
     * `TCP_PORT_OPEN` & `TCP_PORT_OPEN_BANNER`: Mendeteksi port terbuka dan banner layanan.
     * `WEB_SERVER` & `WEB_FRAMEWORK`: Mendeteksi software web server dan framework.
     * `WEBSERVER_STRANGEHEADER`: Menangkap anomali dan kebijakan header non-standar.
     * `SSL_CERTIFICATE_RAW`, `ISSUED`, `ISSUER`: Menangkap kekuatan sertifikat dan enkripsi TLS.
     * `JUNK_FILE` & `INTERESTING_FILE`: Mendeteksi file backup (.bak, .old) yang tertinggal.
     * `VULNERABILITY_*`: Korelasi potensi kerentanan CVE (Low s/d Critical).
     * `HUMAN_NAME` & `EMAILADDR`: Menjaring paparan data pribadi staf/dosen.
   * **Data yang Dimatikan (Unchecked / Non-aktif):** Data kebisingan (*noise*) yang tidak relevan dengan audit keamanan web kampus:
     * `Bitcoin Address` & `Bitcoin Balance` (Data cryptocurrency).
     * `Darknet Mention` & `Tor Exit Node` (Data dark web).
     * `Compromised Password` & `Leaked Site Content` (Data kebocoran akun luar).
     * `Phone Number` & `Physical Address` (Data fisik non-teknis).
4. **Filter 3: Tab By Module (Seleksi 14 Modul Inti Bebas API Key)**
   * **Modul yang Dimatikan (Unchecked):**
     * Seluruh modul yang membutuhkan **API Key berbayar** (terlihat ikon gembok abu-abu: `Shodan`, `VirusTotal`, `Censys`, `AbuseIPDB`, `AbstractAPI`, `AlienVault OTX`, `BinaryEdge`, dll).
     * Modul brute force lambat (`sfp_dnsbrute`, `sfp_tldsearch`).
   * **14 Modul Inti yang Dicentang (Checked):**
     1. `sfp_portscan_tcp`: Memeriksa port aktif terbuka (Port 80 HTTP dan Port 443 HTTPS).
     2. `sfp_webserver`: Mengidentifikasi identitas web server (Nginx).
     3. `sfp_strangeheaders`: Menganalisis header respon non-standar (`permissions-policy`).
     4. `sfp_dnsresolve`: Menyelesaikan nama domain menjadi alamat IP publik target (`103.9.22.82`).
     5. `sfp_sslcert`: Memeriksa masa aktif dan panjang kunci sertifikat TLS (RSA 4096-bit).
     6. `sfp_crt`: Mengunduh catatan Certificate Transparency dari database `crt.sh`.
     7. `sfp_junkfiles`: Mencari file cadangan sementara/sensitif di web root.
     8. `sfp_names`: Mengekstrak nama personil dosen dan civitas akademik.
     9. `sfp_email`: Menjaring alamat email resmi kampus (`@unsoed.ac.id`).
     10. `sfp_spider`: Merayapi seluruh tautan dan hierarki halaman web sasaran.
     11. `sfp_webframework`: Mengidentifikasi framework pemrograman backend.
     12. `sfp_pageinfo`: Menganalisis metadata dokumen HTML halaman depan.
     13. `sfp_whois`: Mengambil informasi kontak pendaftar blok IP di APNIC/IDNIC.
     14. `sfp_subdomain_takeover`: Memeriksa apakah ada subdomain yang mengarah ke layanan mati.


### D. Bedah Temuan Dua Target: Cloud Vercel vs On-Premise Kampus

| Parameter Audit | Target 1: `soedirmanrobotic.com` | Target 2: `komputer.ft.unsoed.ac.id` |
|---|---|---|
| **Karakter Arsitektur** | **Cloud Serverless Edge Platform** (Vercel Anycast Network) | **On-Premise Physical Server** (Pusat Data FT Blater Purbalingga) |
| **Alamat IP Publik** | `76.76.21.21` (Anycast Global, PoP terdekat Singapura `sin1`) | `103.9.22.82` (Dedicated IP Institusi Pendidikan) |
| **Autonomous System (BGP)**| **AS13335** (Cloudflare / Vercel Anycast) | **AS136052** (ID-UNSOED / INHERENT ISP) |
| **Software Web Server** | Serverless Edge Proxy + Next.js Turbopack | **Server: nginx** (Membocorkan banner server) |
| **Volume Rekaman Data** | **14.727 entri data** (106.425 baris log, 17.2 MB) | **1.788 entri data** (~250 KB log) |
| **Alasan Perbedaan Volume Data** | Berbagi 1 IP publik Anycast bersama **ribuan domain pihak ketiga di seluruh dunia**. Modul SpiderFoot menarik ratusan domain tetangga dan 768 file statis Next.js. | Server lokal dedicated institusi kampus, **tidak tercemar oleh domain komersial luar**. Hasil pencarian sangat terfokus dan bersih. |
| **Risiko Reputasi IP (Co-hosting)**| **BERISIKO TINGGI:** Ditemukan **37 domain blacklisted** dan **6 domain malicious** (phishing & judi) yang berbagi IP yang sama. | **BERSIH (0 Blacklisted):** Reputasi IP bersih karena berada di bawah ASN pendidikan nasional. |
| **Kekuatan Enkripsi TLS** | Let's Encrypt Authority, panjang kunci **RSA 2048-bit** | Let's Encrypt Authority, tingkat tinggi **RSA 4096-bit** |
| **Kebocoran Metadata** | Membocorkan internal routing header: `x-matched-path: /` dan direktori `/teams/MANAGER/` | Membocorkan identitas banner `Server: nginx` dan **1 Junk File** (file backup) |
| **Analisis Header Keamanan** | **Tidak ada CSP** dan **Tidak ada X-Frame-Options** (Rentan Clickjacking & XSS) | **Tidak ada CSP** dan **Tidak ada X-Frame-Options**, tetapi memiliki header `Permissions-Policy` |
| **Paparan Data Pribadi (PII)**| 251 nama mahasiswa pengurus robotika & 239 media sosial | **1.331 nama personil** & **47 email dosen** (`@unsoed.ac.id`) |


### E. Kueri SQL Forensik Basis Data Internal `spiderfoot.db`

Seluruh rekaman hasil pemindaian SpiderFoot disimpan secara terpusat pada basis data SQLite lokal:
* **Lokasi Berkas Basis Data:** `~/.spiderfoot/spiderfoot.db` (di folder home pengguna).
* **Tabel Inti:**
  * `tbl_scan_instance`: Menyimpan metadata sesi audit (Scan ID, nama target, waktu mulai/selesai).
  * `tbl_scan_event`: Menyimpan seluruh titik data intelijen hasil ekstraksi modul beserta tipe datanya.
  * `tbl_scan_log`: Menyimpan rekaman riwayat audit log aktivitas modul (*timestamp*, level `INFO`/`WARN`/`ERROR`).

#### 5 Kueri SQL Analisis Forensik Mandiri (Tanpa Web GUI):
1. **Melihat Riwayat Seluruh Sesi Audit yang Pernah Dijalankan:**
   ```sql
   SELECT scan_id, scan_name, target, status, strftime('%Y-%m-%d %H:%M:%S', started/1000, 'unixepoch') AS waktu_mulai FROM tbl_scan_instance;
   ```
2. **Mengekstrak Temuan Kerentanan dan File Sampah (Junk Files):**
   ```sql
   SELECT type, data, confidence FROM tbl_scan_event WHERE scan_instance_id = '971F7834' AND type IN ('JUNK_FILE', 'INTERESTING_FILE', 'VULNERABILITY_GENERAL');
   ```
3. **Mengekstrak Seluruh Alamat Email Dosen/Staf Institusi yang Terekspos:**
   ```sql
   SELECT DISTINCT data FROM tbl_scan_event WHERE scan_instance_id = '971F7834' AND type = 'EMAILADDR' ORDER BY data ASC;
   ```
4. **Melihat Rekaman Error Modul pada Sesi Audit:**
   ```sql
   SELECT component, message FROM tbl_scan_log WHERE scan_instance_id = '971F7834' AND type = 'ERROR';
   ```
5. **Menghitung Total Sebaran Titik Data per Kategori Tipe Data:**
   ```sql
   SELECT type, count(*) AS total FROM tbl_scan_event WHERE scan_instance_id = '971F7834' GROUP BY type ORDER BY total DESC;
   ```


### F. Bank Pertanyaan Ujian Lisan Seputar SpiderFoot

1. **"Apa fungsi utama SpiderFoot dalam siklus audit keamanan informasi?"**
   * *Jawaban:* "SpiderFoot berfungsi sebagai framework otomasi OSINT dan Footprinting pasif maupun aktif. Fungsinya adalah memetakan attack surface target (domain, IP, port terbuka, DNS records, sertifikat SSL, metadata header, hingga kebocoran data personil dan file backup) dari sudut pandang penyerang luar sebelum tahapan eksploitasi dimulai."
2. **"Kenapa hasil pemindaian soedirmanrobotic.com mencapai 14.727 entri sedangkan komputer.ft.unsoed.ac.id hanya 1.788 entri?"**
   * *Jawaban:* "Karena perbedaan arsitektur hosting. Soedirman Robotic Team di-hosting pada Vercel Anycast Global di mana 1 IP publik dipakai bersama oleh ribuan domain luar di dunia, sehingga modul SpiderFoot menarik ratusan domain tetangga (co-hosts) dan file statis Next.js. Sedangkan Web Komputer adalah server fisik on-premise milik Fakultas Teknik di Purbalingga (IP 103.9.22.82) yang terisolasi khusus untuk institusi pendidikan, sehingga hasilnya sangat terfokus dan bersih dari domain komersial tetangga."
3. **"Apa celah keamanan paling kritis yang ditemukan SpiderFoot pada web komputer.ft.unsoed.ac.id?"**
   * *Jawaban:* "Ada tiga temuan kritis: Pertama, ketiadaan header Content-Security-Policy (CSP) dan X-Frame-Options yang membuka risiko serangan Clickjacking dan XSS. Kedua, temuan 1 Junk File oleh modul sfp_junkfiles yang berpotensi membocorkan file cadangan konfigurasi web server. Ketiga, paparan 1.331 nama personil dan 47 alamat email resmi institusi yang rentan dimanfaatkan penyerang untuk serangan rekayasa sosial bertarget (Spear Phishing)."

---

## 13. PANDUAN LENGKAP CARA MENGECEK PATH DAN LOKASI FAST.LOG

Jika dosen bertanya: *"Dari mana kamu tahu berkas `fast.log` itu ada di `/var/log/suricata/fast.log`? Bagaimana cara mengecek jalurnya dari terminal?"*

Ada **5 metode konkret** di Linux untuk membuktikan lokasi jalur (*path*) berkas `fast.log` tersebut secara ilmiah:

---

### A. Metode 1: Memeriksa Berkas Konfigurasi `suricata.yaml` (Metode Resmi)
Suricata menentukan lokasi penyimpanan seluruh berkas log melalui variabel `default-log-dir` dan sub-bagian `outputs` pada konfigurasi masternya.

Perintah eksekusi di terminal Ubuntu:
```bash
grep -E "default-log-dir|filename: fast.log" /etc/suricata/suricata.yaml
```
* **Output yang dihasilkan:**
  ```yaml
  default-log-dir: /var/log/suricata/
        filename: fast.log
  ```
* **Bedah Kata per Kata:**
  * **`grep`** (*Global Regular Expression Print*): Utilitas pencari pola baris teks di Linux.
  * **`-E`** (*Extended regular expressions flag*): Mengaktifkan operator regex lanjutan seperti tanda pipa `|` (*logika OR*).
  * **`"default-log-dir|filename: fast.log"`**: Pola pencarian yang menyaring baris yang memuat kata `default-log-dir` ATAU kata `filename: fast.log`.
  * **`/etc/suricata/suricata.yaml`**: Berkas target konfigurasi master yang dibaca.
* **Penjelasan Logika:**
  Direktori pangkalnya adalah `/var/log/suricata/` dan nama berkas log cepatnya adalah `fast.log`. Jika digabungkan, jalur absolutnya menjadi `/var/log/suricata/fast.log`.

---

### B. Metode 2: Memeriksa Informasi Build Biner Suricata
Biner Suricata menyimpan direktori log *default* yang telah dikompilasi ke dalam kode sumber programnya.

Perintah eksekusi:
```bash
suricata --build-info | grep -i "Default log directory"
```
* **Output yang dihasilkan:**
  ```text
  Default log directory: /var/log/suricata/
  ```
* **Bedah Kata per Kata:**
  * **`suricata`**: Biner aplikasi Suricata.
  * **`--build-info`**: Parameter saklar diagnostik untuk mencetak seluruh informasi kompilasi, pustaka pendukung, dan jalur direktori sistem bawaan Suricata.
  * **`|`** (*Pipeline operator*): Mengalirkan output teks dari perintah sebelah kiri menjadi input bagi perintah di sebelah kanan.
  * **`grep`**: Utilitas penyaring teks.
  * **`-i`** (*Ignore case flag*): Mengabaikan perbedaan huruf besar dan huruf kecil saat mencocokkan frasa `"Default log directory"`.
  * **`"Default log directory"`**: String teks spesifik yang dicari.

---

### C. Metode 3: Mencari Berkas Fisik di Direktori Sistem via `find`
Jika kamu lupa jalurnya dan ingin mencari keberadaan berkas `fast.log` di seluruh folder log sistem operasi Ubuntu:

Perintah eksekusi:
```bash
sudo find /var/log/ -name "fast.log" 2>/dev/null
```
* **Output yang dihasilkan:**
  ```text
  /var/log/suricata/fast.log
  ```
* **Bedah Kata per Kata:**
  * **`sudo`** (*SuperUser DO*): Hak akses root administrator agar diizinkan menyusuri seluruh subfolder sistem di `/var/log/`.
  * **`find`**: Utilitas pencari berkas dan folder berdasarkan kriteria tertentu pada hierarki direktori Linux.
  * **`/var/log/`**: Titik pangkal direktori awal tempat pencarian dimulai.
  * **`-name`** (*Name search flag*): Parameter pencarian berkas berdasarkan kecocokan nama string persis.
  * **`"fast.log"`**: Nama berkas yang dicari.
  * **`2>/dev/null`** (*Error redirection*): Mengarahkan aliran pesan error (deskriptor berkas standar nomor `2` / *stderr*, misalnya pesan *Permission Denied*) ke perangkat lubang hitam sistem `/dev/null` agar tidak mengotori layar terminal.

---

### D. Metode 4: Menginspeksi File Descriptor Proses Aktif via `lsof` (Metode Forensik)
Ini metode paling canggih untuk memukau dosen saat ujian lisan: membuktikan secara fisik bahwa daemon Suricata yang sedang berjalan di RAM benar-benar membuka berkas `fast.log`.

Perintah eksekusi:
```bash
sudo lsof -c suricata | grep "fast.log"
```
* **Output yang dihasilkan:**
  ```text
  suricata 1234 root 5w REG 8,1 45020 131589 /var/log/suricata/fast.log
  ```
* **Bedah Kata per Kata:**
  * **`sudo`**: Hak akses root untuk menginspeksi tabel proses sistem.
  * **`lsof`** (*List Open Files*): Utilitas Linux untuk menampilkan daftar seluruh berkas dan soket jaringan yang sedang dibuka secara aktif oleh proses di memori.
  * **`-c`** (*Command name filter flag*): Parameter penyaring daftar proses berdasarkan nama biner aplikasinya.
  * **`suricata`**: Nama proses yang diinspeksi.
  * **`|`**: Operator pengalir pipa data teks.
  * **`grep`**: Penyaring baris teks.
  * **`"fast.log"`**: Kata kunci yang disaring.
* **Makna Kolom Output:**
  Kolom `5w` membuktikan bahwa file descriptor nomor 5 sedang dibuka oleh daemon Suricata dalam mode tulis (*write mode*) menuju berkas fisik `/var/log/suricata/fast.log`.

---

### E. Metode 5: Memeriksa Ukuran dan Izin Berkas via `ls -lh`
Setelah mengetahui jalurnya, kamu bisa melihat ukuran fisik berkas log dan hak kepemilikannya:

Perintah eksekusi:
```bash
ls -lh /var/log/suricata/fast.log
```
* **Output yang dihasilkan:**
  ```text
  -rw-r----- 1 root root 44K Nov 11 03:15 /var/log/suricata/fast.log
  ```
* **Bedah Kata per Kata:**
  * **`ls`** (*List*): Utilitas Linux untuk mencetak daftar isi berkas atau folder.
  * **`-l`** (*Long listing format flag*): Menampilkan informasi secara mendalam (mode izin berkas, jumlah hard link, pemilik, grup, ukuran berkas, dan stempel waktu modifikasi).
  * **`-h`** (*Human-readable flag*): Menampilkan ukuran berkas dalam unit yang mudah dibaca manusia (K untuk Kilobyte, M untuk Megabyte), bukan dalam angka byte mentah.
  * **`/var/log/suricata/fast.log`**: Jalur absolut berkas target.

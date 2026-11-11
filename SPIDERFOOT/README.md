# PANDUAN LENGKAP FOOTPRINTING & OSINT: SPIDERFOOT V4.0.0
**Materi:** Open Source Intelligence (OSINT) & Attack Surface Mapping  
**Penulis:** Afif Nur Rahman (H1H024016)  
**Target Lab:** Universitas Jenderal Soedirman  
**Dokumentasi Terkait:** [Kembali ke README Utama (Suricata & DVWA)](../README.md)

---

## DAFTAR ISI
1. [Konsep Dasar Footprinting & Pengintaian OSINT](#1-konsep-dasar-footprinting--pengintaian-osint)
2. [Bedah Perintah Instalasi & Troubleshooting Dependensi Kata per Kata](#2-bedah-perintah-instalasi--troubleshooting-dependensi-kata-per-kata)
3. [Bedah Konfigurasi 3 Filter pada Halaman New Scan](#3-bedah-konfigurasi-3-filter-pada-halaman-new-scan)
4. [Bedah Temuan Komparatif Dua Target: Cloud Vercel vs On-Premise Kampus](#4-bedah-temuan-komparatif-dua-target-cloud-vercel-vs-on-premise-kampus)
5. [Kueri SQL Forensik Basis Data Internal spiderfoot.db](#5-kueri-sql-forensik-basis-data-internal-spiderfootdb)
6. [Bank Pertanyaan Ujian Lisan Seputar SpiderFoot](#6-bank-pertanyaan-ujian-lisan-seputar-spiderfoot)

---

## 1. KONSEP DASAR FOOTPRINTING & PENGINTAIAN OSINT

* **Footprinting:** Tahap awal pengumpulan informasi secara komprehensif mengenai target (jaringan, sistem, perangkat lunak, dan organisasi) sebelum melancarkan serangan siber. Merupakan fase pertama dalam metodologi *Cyber Kill Chain* dan *PTES (Penetration Testing Execution Standard)*.
* **OSINT (Open Source Intelligence):** Pengumpulan data intelijen yang bersumber secara legal dari catatan publik terbuka (DNS, SSL Certificate Transparency, arsip mesin pencari, registri WHOIS, dan rute BGP) tanpa melakukan eksploitasi sistem.
* **Passive vs Active Reconnaissance:**
  * *Passive Recon:* Mengumpulkan data tanpa berinteraksi langsung dengan server sasaran (misal query ke crt.sh atau Shodan). Tidak meninggalkan jejak log di server target.
  * *Active Recon:* Berinteraksi langsung dengan server sasaran (seperti melakukan port scanning TCP dan HTTP banner grabbing). Meninggalkan jejak log di firewall/IDS target.

---

## 2. BEDAH PERINTAH INSTALASI & TROUBLESHOOTING DEPENDENSI KATA PER KATA

### A. Mengunduh Kode Sumber SpiderFoot
```bash
git clone https://github.com/smicallef/spiderfoot.git
```
* **`git`**: Program sistem pengontrol versi terdistribusi.
* **`clone`**: Perintah untuk mengunduh salinan repositori penuh dari internet ke komputer lokal.
* **`https://github.com/smicallef/spiderfoot.git`**: Alamat repositori resmi framework SpiderFoot yang dikembangkan oleh Steve Micallef.

---

### B. Isolasi Virtual Environment Python
```bash
python -m venv sf-env
```
* **`python`**: Interpreter bahasa pemrograman Python.
* **`-m`** (*Module flag*): Parameter saklar yang memerintahkan Python untuk mengeksekusi sebuah modul pustaka standar sebagai skrip mandiri.
* **`venv`**: Modul pustaka bawaan Python untuk membuat lingkungan virtual (*Virtual Environment*) yang terisolasi dari direktori sistem utama.
* **`sf-env`**: Nama folder lokal tempat pustaka dan biner Python terisolasi disimpan.

---

### C. Aktivasi Virtual Environment
* Di Windows PowerShell:
  ```powershell
  .\sf-env\Scripts\Activate.ps1
  ```
* Di Linux / macOS:
  ```bash
  source sf-env/bin/activate
  ```
* **Fungsi:** Mengubah environment variable `PATH` agar perintah `python` dan `pip` mengarah ke folder lokal `sf-env`, ditandai dengan munculnya prefiks `(sf-env)` di awal baris terminal prompt.

---

### D. Pembaruan Paket Manajer pip
```bash
python -m pip install --upgrade pip
```
* **`python -m pip`**: Menjalankan modul penginstal paket Python (*pip*).
* **`install`**: Subperintah untuk memasang atau memperbarui pustaka.
* **`--upgrade`**: Opsi saklar untuk memaksa pip memperbarui dirinya sendiri ke versi stabil terbaru yang tersedia di repositori PyPI.
* **`pip`**: Nama paket manajer yang diperbarui.

---

### E. Bedah Dua Kendala Teknis (*Troubleshooting*)
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

---

### F. Menjalankan Server Web GUI SpiderFoot
```bash
python sf.py -l 127.0.0.1:5001
```
* **`python`**: Biner interpreter Python aktif.
* **`sf.py`**: Berkas skrip utama peluncur SpiderFoot (*SpiderFoot Core Script*).
* **`-l`** (*Listen address & port flag*): Parameter untuk menentukan alamat IP pengikatan (*binding host*) dan nomor port web server internal.
* **`127.0.0.1:5001`**: Mengikat layanan web server CherryPy pada alamat loopback lokal `127.0.0.1` pada port **`5001`**. Layanan diakses via browser dengan mengetikkan `http://127.0.0.1:5001/`.

---

## 3. BEDAH KONFIGURASI 3 FILTER PADA HALAMAN NEW SCAN

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

---

## 4. BEDAH TEMUAN KOMPARATIF DUA TARGET: CLOUD VERCEL VS ON-PREMISE KAMPUS

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

---

## 5. KUERI SQL FORENSIK BASIS DATA INTERNAL `spiderfoot.db`

Seluruh rekaman hasil pemindaian SpiderFoot disimpan secara terpusat pada basis data SQLite lokal:
* **Lokasi Berkas Basis Data:** `~/.spiderfoot/spiderfoot.db` (di folder home pengguna).
* **Tabel Inti:**
  * `tbl_scan_instance`: Menyimpan metadata sesi audit (Scan ID, nama target, waktu mulai/selesai).
  * `tbl_scan_event`: Menyimpan seluruh titik data intelijen hasil ekstraksi modul beserta tipe datanya.
  * `tbl_scan_log`: Menyimpan rekaman riwayat audit log aktivitas modul (*timestamp*, level `INFO`/`WARN`/`ERROR`).

### 5 Kueri SQL Analisis Forensik Mandiri (Tanpa Web GUI):

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

---

## 6. BANK PERTANYAAN UJIAN LISAN SEPUTAR SPIDERFOOT

1. **"Apa fungsi utama SpiderFoot dalam siklus audit keamanan informasi?"**
   * *Jawaban:* "SpiderFoot berfungsi sebagai framework otomasi OSINT dan Footprinting pasif maupun aktif. Fungsinya adalah memetakan attack surface target (domain, IP, port terbuka, DNS records, sertifikat SSL, metadata header, hingga kebocoran data personil dan file backup) dari sudut pandang penyerang luar sebelum tahapan eksploitasi dimulai."
2. **"Kenapa hasil pemindaian soedirmanrobotic.com mencapai 14.727 entri sedangkan komputer.ft.unsoed.ac.id hanya 1.788 entri?"**
   * *Jawaban:* "Karena perbedaan arsitektur hosting. Soedirman Robotic Team di-hosting pada Vercel Anycast Global di mana 1 IP publik dipakai bersama oleh ribuan domain luar di dunia, sehingga modul SpiderFoot menarik ratusan domain tetangga (co-hosts) dan file statis Next.js. Sedangkan Web Komputer adalah server fisik on-premise milik Fakultas Teknik di Purbalingga (IP 103.9.22.82) yang terisolasi khusus untuk institusi pendidikan, sehingga hasilnya sangat terfokus dan bersih dari domain komersial tetangga."
3. **"Apa celah keamanan paling kritis yang ditemukan SpiderFoot pada web komputer.ft.unsoed.ac.id?"**
   * *Jawaban:* "Ada tiga temuan kritis: Pertama, ketiadaan header Content-Security-Policy (CSP) dan X-Frame-Options yang membuka risiko serangan Clickjacking dan XSS. Kedua, temuan 1 Junk File oleh modul sfp_junkfiles yang berpotensi membocorkan file cadangan konfigurasi web server. Ketiga, paparan 1.331 nama personil dan 47 alamat email resmi institusi yang rentan dimanfaatkan penyerang untuk serangan rekayasa sosial bertarget (Spear Phishing)."

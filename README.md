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
   - [Rule 1.A: SQL Injection Tautology Bypass (Video Dosen - sid:1000021)](#rule-1a-sql-injection-tautology-bypass-sid1000021)
   - [Rule 1.B: SQL Injection UNION SELECT Operator (Bab IX Modul - sid:1000004)](#rule-1b-sql-injection-union-select-operator-bab-ix-modul---sid1000004)
   - [Rule 1.C: SQL Injection Encoded Quote %27 (Bab IX Modul - sid:1000005)](#rule-1c-sql-injection-encoded-quote-27-bab-ix-modul---sid1000005)
   - [Rule 1.D: SQL Injection DB Fingerprinting version() (Bab IX Modul - sid:1000006)](#rule-1d-sql-injection-db-fingerprinting-version-bab-ix-modul---sid1000006)
   - [Rule 1.E: SQL Injection Time-Based Blind sleep() (Bab IX Modul - sid:1000007)](#rule-1e-sql-injection-time-based-blind-sleep-bab-ix-modul---sid1000007)
   - [Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)](#rule-2-reflected-xss-event-handler-bypass-sid1000022)
   - [Rule 3: CSRF Unauthorized Password Change (sid:1000023)](#rule-3-csrf-unauthorized-password-change-sid1000023)
   - [Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)](#rule-4-dos-tcp-syn-flood-port-80-dvwa-sid1000024)
   - [Rule 5: Mode IPS - SQL Injection Dropped (sid:1000025 rev:1)](#rule-5-mode-ips---sql-injection-dropped-sid1000025-rev1)
10. [Konseptual Arsitektur: Mode IDS vs Mode IPS](#10-konseptual-arsitektur-mode-ids-vs-mode-ips)
11. [FAQ Ujian Lisan: Menjalankan Suricata Mode IDS vs Memantau Log (`tail -f`)](#11-faq-ujian-lisan-menjalankan-suricata-mode-ids-vs-memantau-log)
12. [Panduan Lengkap Cara Mengecek Path dan Lokasi fast.log](#12-panduan-lengkap-cara-mengecek-path-dan-lokasi-fastlog)
   - [A. Metode 1: Memeriksa Berkas Konfigurasi suricata.yaml (Metode Resmi)](#a-metode-1-memeriksa-berkas-konfigurasi-suricatayaml-metode-resmi)
   - [B. Metode 2: Memeriksa Informasi Build Biner Suricata](#b-metode-2-memeriksa-informasi-build-biner-suricata)
   - [C. Metode 3: Mencari Berkas Fisik di Direktori Sistem via find](#c-metode-3-mencari-berkas-fisik-di-direktori-sistem-via-find)
   - [D. Metode 4: Menginspeksi File Descriptor Proses Aktif via lsof (Metode Forensik)](#d-metode-4-menginspeksi-file-descriptor-proses-aktif-via-lsof-metode-forensik)
   - [E. Metode 5: Memeriksa Ukuran dan Izin Berkas via ls -lh](#e-metode-5-memeriksa-ukuran-dan-izin-berkas-via-ls--lh)
13. [Panduan Custom Rules Eksplorasi: Deteksi & Pemblokiran Akses Media Sosial (Instagram & Facebook via TLS SNI, DNS, dan HTTP)](#13-panduan-custom-rules-eksplorasi-deteksi--pemblokiran-akses-media-sosial-instagram--facebook-via-tls-sni-dns-dan-http)
   - [A. Tantangan Teknis: Mengapa Tidak Bisa Menggunakan http.uri?](#a-tantangan-teknis-mengapa-tidak-bisa-menggunakan-httpuri)
   - [B. Solusi Layer 1: Deteksi via TLS SNI (Server Name Indication) Port 443 (Metode Utama)](#b-solusi-layer-1-deteksi-via-tls-sni-server-name-indication-port-443-metode-utama)
   - [C. Solusi Layer 2: Deteksi via DNS Query Port 53 (Sebelum Koneksi Terbentuk)](#c-solusi-layer-2-deteksi-via-dns-query-port-53-sebelum-koneksi-terbentuk)
   - [D. Solusi Layer 3: Deteksi via HTTP Host Header Port 80](#d-solusi-layer-3-deteksi-via-http-host-header-port-80)
   - [E. Aturan Mode IPS: Pemblokiran Akses Media Sosial (Action Drop)](#e-aturan-mode-ips-pemblokiran-akses-media-sosial-action-drop)
   - [F. Mengapa Mengetik "facebook.com" di Firefox Kali Linux Tidak Menghasilkan Alert?](#f-mengapa-mengetik-facebookcom-di-firefox-kali-linux-tidak-menghasilkan-alert)
   - [G. Dua Cara Praktik Menguji Rule Facebook di Lab (100% Berhasil)](#g-dua-cara-praktik-menguji-rule-facebook-di-lab-100-berhasil)
14. [Teori & Analisis Komparatif 3 Serangan Web: SQLi, XSS, dan CSRF](#14-teori--analisis-komparatif-3-serangan-web-sqli-xss-dan-csrf)
   - [A. SQL Injection (SQLi) - Konsep, Lokasi Eksekusi, dan Dampak](#a-sql-injection-sqli---konsep-lokasi-eksekusi-dan-dampak)
   - [B. Cross-Site Scripting (XSS) - Konsep, Lokasi Eksekusi, dan Dampak](#b-cross-site-scripting-xss---konsep-lokasi-eksekusi-dan-dampak)
   - [C. Cross-Site Request Forgery (CSRF) - Konsep, Lokasi Eksekusi, dan Dampak](#c-cross-site-request-forgery-csrf---konsep-lokasi-eksekusi-dan-dampak)
   - [D. Tabel Matriks Perbandingan Pembeda Utama (SQLi vs XSS vs CSRF)](#d-tabel-matriks-perbandingan-pembeda-utama-sqli-vs-xss-vs-csrf)
   - [E. Analisis Eksploitasi Berantai (Chained Attack XSS ke CSRF pada Video Dosen)](#e-analisis-eksploitasi-berantai-chained-attack-xss-ke-csrf-pada-video-dosen)
   - [F. Strategi Pertahanan & Mitigasi Resmi Masing-Masing Kerentanan](#f-strategi-pertahanan--mitigasi-resmi-masing-masing-kerentanan)

> **Materi Khusus Footprinting & OSINT:** Dokumentasi lengkap mengenai instalasi, konfigurasi 3 filter, analisis SQLite `spiderfoot.db`, dan perbandingan temuan SpiderFoot v4.0.0 dipisahkan ke dalam folder khusus: [SPIDERFOOT/README.md](SPIDERFOOT/README.md).

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

### F. Perekaman Jejak Paket Serangan Jaringan via tcpdump
```bash
sudo tcpdump -i eth0 -w synflood.pcap host 192.168.2.3 and port 80
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk mengaktifkan antarmuka kartu jaringan dalam mode sadap (*promiscuous mode*).
* **`tcpdump`**: Program penganalisis paket jaringan CLI paling populer di Linux untuk menyadap (*sniffing*) dan merekam paket data yang melintas.
* **`-i`** (*Interface flag*): Menentukan kartu jaringan yang disadap.
* **`eth0`**: Nama kartu jaringan aktif di VM Kali Linux yang mengarah ke lab.
* **`-w`** (*Write to file flag*): Memerintahkan `tcpdump` agar tidak mencetak teks paket mentah ke layar terminal, melainkan menyimpannya ke dalam berkas biner `.pcap`.
* **`synflood.pcap`**: Nama berkas biner PCAP (*Packet Capture*) hasil rekaman yang nantinya bisa dibuka dan dianalisis di Wireshark.
* **`host`** (*BPF Primitive keyword*): Filter sintaks *Berkeley Packet Filter (BPF)* untuk membatasi pencatatan hanya pada host tertentu.
* **`192.168.2.3`**: Alamat IP host target yang disaring.
* **`and`** (*BPF Logical Operator*): Operator logika DAN untuk menggabungkan dua kondisi filter.
* **`port`** (*BPF Port Primitive keyword*): Filter pembatas nomor port.
* **`80`**: Nilai port tujuan yang difilter (hanya merekam lalu lintas HTTP port 80).

---

### G. Perintah Serangan DoS Xmas Tree Flood via hping3
```bash
sudo hping3 -F -P -U --flood -p 80 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`hping3`**: Program generator paket TCP/IP kustom.
* **`-F`** (*Set FIN Flag*): Mengaktifkan bendera **FIN** (*Finish*) pada header TCP.
* **`-P`** (*Set PSH Flag*): Mengaktifkan bendera **PSH** (*Push*) pada header TCP.
* **`-U`** (*Set URG Flag*): Mengaktifkan bendera **URG** (*Urgent*) pada header TCP.
* **`--flood`** (*Flood mode*): Mengirimkan paket kombinasi FIN+PSH+URG secepat kapasitas bandwidth antarmuka tanpa jeda waktu. Disebut *Xmas Attack* karena kombinasi ketiga bendera yang menyala serentak dianalogikan seperti lampu pohon natal yang berkedip, membebani CPU kernel korban yang kebingungan memproses anomali state koneksi.
* **`-p`** (*Destination Port Flag*): Saklar penunjuk nomor port.
* **`80`**: Nomor port web server HTTP target.
* **`192.168.2.3`**: Alamat IP server sasaran.

---

### H. Perintah Serangan DoS ICMP Flood via hping3
```bash
sudo hping3 --icmp --flood 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`hping3`**: Biner perakit paket data mentah.
* **`--icmp`** (*ICMP Mode Flag*): Memerintahkan `hping3` untuk menyusun paket protokol ICMP (*Echo Request*), bukan paket TCP.
* **`--flood`** (*Flood Mode*): Mengirimkan jutaan paket ping per detik tanpa jeda waktu dan tanpa menunggu balasan paket, menghabiskan alokasi bandwidth penerimaan (*bandwidth exhaustion*).
* **`192.168.2.3`**: Alamat IP server korban yang dibanjiri ICMP ping.

---

### I. Perintah Serangan DoS UDP Flood ke Port 53 via hping3
```bash
sudo hping3 --udp --flood -p 53 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`hping3`**: Biner pembuat paket mentah.
* **`--udp`** (*UDP Mode Flag*): Menyusun paket protokol transport UDP (*User Datagram Protocol*).
* **`--flood`** (*Flood Mode*): Menembakkan paket UDP secepat mungkin tanpa menunggu balasan.
* **`-p`** (*Destination Port Flag*): Saklar penunjuk port tujuan.
* **`53`**: Port layanan DNS server target.
* **`192.168.2.3`**: Alamat IP server tujuan.

---

### J. Perintah Eksploitasi SQL Injection Otomatis via Sqlmap
```bash
sqlmap -u "http://192.168.2.3/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=fl52qlkmsings5cjtagvaftpb4; security=low" --batch --dbs
```
* **`sqlmap`**: Alat penetrasi open-source otomatis untuk mendeteksi dan mengeksploitasi kerentanan SQL Injection serta mengambil alih database server.
* **`-u`** (*Target URL Flag*): Menentukan alamat URL endpoint aplikasi web yang memiliki parameter rentan.
* **`"..."`**: URL lengkap menuju modul SQLi DVWA beserta parameter yang akan diuji (`id=1`).
* **`--cookie`** (*HTTP Cookie Header Flag*): Mengirimkan data cookie sesi peramban. Wajib disertakan karena aplikasi DVWA mengharuskan pengguna terautentikasi (membutuhkan nilai cookie sesi `PHPSESSID` dan tingkat keamanan `security=low`).
* **`--batch`** (*Non-interactive Batch Mode*): Menginstruksikan `sqlmap` agar tidak pernah berhenti menanyakan pertanyaan konfirmasi kepada pengguna di terminal, melainkan otomatis memilih jawaban bawaan (*default answer*).
* **`--dbs`** (*Enumerate Databases Flag*): Perintah DBMS footprinting untuk mengekstrak dan menampilkan seluruh daftar nama skema basis data (*databases*) yang ada di dalam server MariaDB/MySQL.

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

### I. Pemasangan Repositori PPA Resmi Suricata (OISF Stable)
```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk menambahkan sumber repositori baru ke berkas konfigurasi sistem `/etc/apt/sources.list.d/`.
* **`add-apt-repository`**: Program utilitas Linux untuk menambahkan repositori *Personal Package Archive (PPA)* pihak ketiga ke dalam sistem manajemen paket APT.
* **`-y`** (*Automatic Yes flag*): Mengonfirmasi penambahan kunci autentikasi GPG repositori secara otomatis tanpa berhenti meminta konfirmasi tombol Enter.
* **`ppa:oisf/suricata-stable`**: Alamat PPA resmi yang dikelola langsung oleh *Open Information Security Foundation (OISF)* penyedia paket rilis stabil terbaru Suricata.

---

### J. Pembaruan Signature Database Resmi via suricata-update
```bash
sudo suricata-update
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk menulis berkas signature ke direktori sistem `/var/lib/suricata/rules/`.
* **`suricata-update`**: Program utilitas resmi bawaan Suricata untuk mengunduh, menggabungkan (*bundling*), dan memperbarui puluhan ribu aturan signature ancaman siber terbaru dari repositori komunitas *Emerging Threats (ET Open)*.

---

### K. Checklist Hardening Awal Firewall UFW (Bab 1 Modul Praktikum Hal. 10)
```bash
sudo ufw allow 22,80,443/tcp && sudo ufw enable
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk mengonfigurasi firewall host.
* **`ufw`** (*Uncomplicated Firewall*): Antarmuka baris perintah yang menyederhanakan konfigurasi tabel firewall iptables di Ubuntu.
* **`allow`**: Aturan izin yang memperbolehkan lalu lintas paket masuk (*ingress traffic*).
* **`22,80,443/tcp`**: Daftar nomor port yang dibuka secara selektif khusus protokol TCP:
  * Port `22`: Layanan remote administrasi SSH.
  * Port `80`: Layanan web server HTTP DVWA.
  * Port `443`: Layanan web server terenkripsi HTTPS.
* **`&&`** (*Operator Logika AND*): Operator shell penjamin urutan eksekusi perintah berikutnya jika perintah pertama sukses.
* **`sudo`** (*SuperUser DO*): Hak akses root.
* **`ufw`**: Program firewall UFW.
* **`enable`**: Mengaktifkan firewall UFW dan memasangnya agar otomatis menyala saat sistem dinyalakan (*booting*). Port lain di luar daftar di atas otomatis ditolak (*default deny policy*).

---

### L. Pencatatan Baseline Layanan Jaringan Aktif via ss (Bab 1 Modul Praktikum Hal. 10)
```bash
sudo ss -tulpn > baseline_services.txt
```
* **`sudo`** (*SuperUser DO*): Hak akses root untuk melihat nama proses dan PID seluruh program sistem.
* **`ss`** (*Socket Statistics*): Utilitas modern pemeriksa soket jaringan Linux (pengganti utilitas lawas `netstat`).
* **`-t`** (*TCP sockets flag*): Memfilter hanya soket protokol transport TCP.
* **`-u`** (*UDP sockets flag*): Memfilter soket protokol transport UDP.
* **`-l`** (*Listening sockets flag*): Hanya menampilkan soket yang berstatus mendengarkan (*LISTENING* / siap menerima koneksi masuk).
* **`-p`** (*Process flag*): Menampilkan nama proses dan nomor PID aplikasi pemilik soket tersebut (misal `apache2`, `suricata`, `mariadbd`).
* **`-n`** (*Numeric flag*): Menampilkan alamat IP dan nomor port dalam bentuk angka murni tanpa mencoba menerjemahkannya ke nama domain (mencegah lag resolusi DNS).
* **`>`** (*Output Redirection Operator*): Mengarahkan keluaran teks hasil perintah dari layar terminal untuk ditulis dan disimpan ke dalam sebuah berkas teks baru.
* **`baseline_services.txt`**: Nama berkas teks tempat menyimpan daftar layanan normal awal (*baseline*) sebagai pembanding forensik jika sistem disusupi di masa depan.

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

### Rule 1.A: SQL Injection Tautology Bypass (sid:1000021)
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

### Rule 1.B: SQL Injection UNION SELECT Operator (Bab IX Modul - sid:1000004)
```text
alert http any any -> $HOME_NET 80 (msg:"SQL INJECTION ATTEMPT - UNION SELECT DETECTED"; flow:to_server,established; http.uri; content:"UNION"; nocase; http.uri; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000004; rev:1;)
```
* **`alert`**: Aksi Mode IDS, mencatat peringatan ke dalam `fast.log` tanpa memutus koneksi peramban.
* **`http`**: Parser protokol lapisan aplikasi HTTP Suricata.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port klien peramban pengirim dari nomor port acak berapa saja.
* **`->`** (*Direction Operator*): Arah lalu lintas paket satu arah dari klien penyerang menuju server korban.
* **`$HOME_NET`**: Alamat IP server web korban yang dilindungi (`192.168.2.3/32`).
* **`80`**: Nomor port layanan web HTTP Apache target.
* **`msg:"SQL INJECTION ATTEMPT - UNION SELECT DETECTED"`**: Teks pesan peringatan deskriptif yang dicetak ke `fast.log`.
* **`flow:to_server,established;`**:
  * `to_server`: Hanya memeriksa paket permintaan yang dikirim dari arah klien menuju server web.
  * `established`: Memastikan koneksi TCP telah terjalin sah melalui Three-Way Handshake.
* **`http.uri;`**: *Sticky buffer*. Mengarahkan pencarian muatan string hanya pada area pointer memori baris URL path dan parameter query.
* **`content:"UNION";`**: Pola teks pertama yang dicari, mencocokkan kata kunci operator SQL `UNION`.
* **`nocase;`**: Mengabaikan perbedaan huruf besar dan kecil untuk kata kunci `UNION`.
* **`http.uri;`**: Menegaskan kembali sticky buffer untuk evaluasi pencocokan pola teks kedua.
* **`content:"SELECT";`**: Pola teks kedua yang dicari, mencocokkan kata kunci operator SQL `SELECT`.
* **`nocase;`**: Mengabaikan kapitalisasi huruf untuk kata kunci `SELECT`.
* **`distance:0;`** (*Relative distance modifier*): Parameter krusial yang menentukan bahwa pencarian kata `SELECT` harus dimulai tepat dari posisi karakter terakhir kata `UNION` ditemukan (jarak offset 0 byte atau lebih di depannya). Mencegah salah deteksi jika kata `SELECT` muncul sebelum kata `UNION`.
* **`classtype:web-application-attack;`**: Kategori serangan aplikasi web (otomatis memetakan ke tingkat keparahan **Priority 1 / High**).
* **`sid:1000004;`**: Signature ID unik 1000004.
* **`rev:1;`**: Nomor versi revisi rule ke-1.

---

### Rule 1.C: SQL Injection Encoded Quote %27 (Bab IX Modul - sid:1000005)
```text
alert http any any -> $HOME_NET 80 (msg:"SQL INJECTION ATTEMPT - Quote/Encoded Character Detected"; http.uri; content:"%27"; nocase; classtype:web-application-attack; sid:1000005; rev:1;)
```
* **`alert`**: Aksi Mode IDS, mencatat ke log tanpa membuang paket.
* **`http`**: Parser protokol lapisan aplikasi HTTP Suricata.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port pengirim klien penyerang.
* **`->`** (*Direction Operator*): Arah paket satu arah dari penyerang ke server.
* **`$HOME_NET`**: Alamat IP server web target yang dilindungi (`192.168.2.3/32`).
* **`80`**: Nomor port layanan web HTTP target.
* **`msg:"SQL INJECTION ATTEMPT - Quote/Encoded Character Detected"`**: Teks pesan peringatan di file log.
* **`http.uri;`**: *Sticky buffer*. Mengarahkan pencarian string secara spesifik hanya pada buffer URL.
* **`content:"%27";`**: Pola teks yang dicari, mencocokkan representasi URL Encoding dari karakter kutip tunggal (`'`). Karakter ini adalah indikator awal bahwa penyerang mencoba merusak pembungkus string kueri SQL asli.
* **`nocase;`**: Mengabaikan perbedaan huruf kapital (misal `%27` atau `%2F`).
* **`classtype:web-application-attack;`**: Kategori serangan aplikasi web (Priority 1).
* **`sid:1000005;`**: Signature ID unik 1000005.
* **`rev:1;`**: Nomor revisi ke-1.

---

### Rule 1.D: SQL Injection DB Fingerprinting version() (Bab IX Modul - sid:1000006)
```text
alert http any any -> $HOME_NET 80 (msg:"SQL INJECTION ATTEMPT - DB Fingerprinting Function Detected"; http.uri; content:"version("; nocase; classtype:web-application-attack; sid:1000006; rev:1;)
```
* **`alert`**: Aksi Mode IDS, mencatat insiden ke log.
* **`http`**: Protokol aplikasi web HTTP.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port klien penyerang.
* **`->`** (*Direction Operator*): Arah aliran paket menuju server.
* **`$HOME_NET`**: Alamat IP server web target.
* **`80`**: Port layanan web HTTP target.
* **`msg:"SQL INJECTION ATTEMPT - DB Fingerprinting Function Detected"`**: Pesan alert di log.
* **`http.uri;`**: *Sticky buffer* penunjuk area URL string.
* **`content:"version(";`**: Pola teks yang mencocokkan fungsi bawaan MySQL/MariaDB `version()`. Fungsi ini digunakan penyerang untuk memetakan versi database guna mencari eksploitasi CVE lanjutan.
* **`nocase;`**: Case-insensitive untuk parameter content.
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000006;`**: Signature ID unik 1000006.
* **`rev:1;`**: Nomor revisi ke-1.

---

### Rule 1.E: SQL Injection Time-Based Blind sleep() (Bab IX Modul - sid:1000007)
```text
alert http any any -> $HOME_NET 80 (msg:"SQL INJECTION ATTEMPT - Time-Based Blind sleep() Detected"; flow:to_server,established; http.uri; content:"sleep("; nocase; classtype:web-application-attack; sid:1000007; rev:1;)
```
* **`alert`**: Aksi Mode IDS, catat insiden ke log tanpa memutus koneksi.
* **`http`**: Protokol lapisan aplikasi web HTTP.
* **`any` (Source IP)**: Alamat IP penyerang dari mana saja.
* **`any` (Source Port)**: Port acak klien penyerang.
* **`->`** (*Direction Operator*): Arah paket dari penyerang ke server.
* **`$HOME_NET`**: Alamat IP server web target yang dilindungi.
* **`80`**: Nomor port layanan web HTTP target.
* **`msg:"SQL INJECTION ATTEMPT - Time-Based Blind sleep() Detected"`**: Teks pesan peringatan di file log.
* **`flow:to_server,established;`**:
  * `to_server`: Memeriksa hanya paket permintaan yang mengalir menuju server.
  * `established`: Memastikan jabat tangan TCP Three-Way Handshake telah selesai.
* **`http.uri;`**: *Sticky buffer* inspeksi pada baris URL.
* **`content:"sleep(";`**: Pola teks yang mencocokkan fungsi penunda waktu MySQL `sleep()`. Fungsi ini disuntikkan penyerang pada teknik *Time-Based Blind SQLi* untuk mengekstrak data huruf-demi-huruf dengan mengukur jeda waktu respons web server.
* **`nocase;`**: Mengabaikan kapitalisasi huruf pada parameter content.
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000007;`**: Signature ID unik 1000007.
* **`rev:1;`**: Nomor revisi ke-1.

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

### Rule 5: Mode IPS - SQL Injection Dropped (sid:1000025 rev:1)
```text
drop http any any -> $HOME_NET 80 (msg:"[DVWA IPS BLOCK] SQL Injection Dropped"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000025; rev:1;)
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
* **`sid:1000025;`**: Signature ID unik 1000025 (diberi nomor SID mandiri agar tidak bentrok atau menimpa Rule IDS 1000021 saat kedua rule berada dalam satu berkas `local.rules`).
* **`rev:1;`**: Nomor revisi ke-1 untuk rule mode IPS.

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


## 12. PANDUAN LENGKAP CARA MENGECEK PATH DAN LOKASI FAST.LOG

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

---

## 13. PANDUAN CUSTOM RULES EKSPLORASI: DETEKSI & PEMBLOKIRAN AKSES MEDIA SOSIAL (INSTAGRAM & FACEBOOK VIA TLS SNI, DNS, DAN HTTP)

Ini adalah skenario eksplorasi paling populer yang sering diujikan dosen:
> *"Bagaimana cara membuat custom rule Suricata untuk mendeteksi atau memblokir pengguna di jaringan lokal yang mencoba membuka Instagram atau Facebook?"*

---

### A. Tantangan Teknis: Mengapa Tidak Bisa Menggunakan `http.uri`?

Mahasiswa yang belum paham arsitektur jaringan sering membuat kesalahan fatal dengan menulis rule seperti ini:
```text
# SALAH TOTAL (TIDAK AKAN PERNAH BERBUNYI):
alert http any any -> any 80 (msg:"Buka IG"; http.uri; content:"instagram.com"; sid:1000099; rev:1;)
```
* **Penyebab Kegagalan:**
  1. Layanan Instagram dan Facebook **100% menggunakan protokol HTTPS terenkripsi pada Port 443 TCP**, bukan HTTP Port 80.
  2. Pada HTTPS, seluruh konten HTTP (URL path, query parameter, dan cookie) dienkripsi menggunakan algoritma TLS/SSL.
  3. Mesin parser `http.uri` Suricata **tidak bisa membaca data yang terenkripsi**, sehingga rule di atas tidak akan pernah memicu alert.

---

### B. Solusi Layer 1: Deteksi via TLS SNI (Server Name Indication) Port 443 (Metode Utama)

Meskipun lalu lintas HTTPS dienkripsi, terdapat celah pada proses pembentukan jabat tangan TLS (*TLS Handshake RFC 6066*):
* Ketika peramban klien mengirimkan paket pertama **Client Hello**, peramban wajib menyertakan ekstensi **Server Name Indication (SNI)**.
* Ekstensi SNI ini memuat nama domain tujuan (misal: `www.instagram.com`) dalam bentuk **teks polos (*plaintext / unencrypted*)** sebelum proses enkripsi simetris dimulai.
* Suricata memiliki parser protokol lapisan aplikasi khusus bernama **`tls`** dan sticky buffer khusus bernama **`tls.sni`**.

#### 1. Rule Deteksi Akses Instagram via TLS SNI:
```text
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"[POLICY VIOLATION] Akses ke Instagram Terdeteksi via TLS SNI"; flow:established,to_server; tls.sni; content:"instagram.com"; nocase; classtype:policy-violation; sid:1000040; rev:1;)
```
* **Bedah Kata per Kata:**
  * **`alert`**: Aksi Mode IDS, catat insiden ke berkas log tanpa memutus koneksi.
  * **`tls`**: Parser protokol lapisan aplikasi TLS/SSL Suricata.
  * **`$HOME_NET`** (Source IP): Komputer pengguna/karyawan/mahasiswa di dalam jaringan lokal yang membuka Instagram.
  * **`any`** (Source Port): Nomor port klien peramban pengguna yang acak.
  * **`->`**: Arah lalu lintas paket keluar dari pengguna lokal menuju server luar.
  * **`$EXTERNAL_NET`** (Destination IP): Server milik Meta/Instagram di internet publik.
  * **`443`** (Destination Port): Port standar protokol web terenkripsi HTTPS.
  * **`msg:"[POLICY VIOLATION] Akses ke Instagram Terdeteksi via TLS SNI"`**: Teks pesan peringatan di file log.
  * **`flow:established,to_server;`**:
    * `established`: Memastikan jabat tangan TCP Three-Way Handshake telah selesai.
    * `to_server`: Hanya memeriksa paket permintaan yang keluar dari klien menuju server internet.
  * **`tls.sni;`**: *Sticky buffer*. Mengarahkan pencarian string secara spesifik hanya pada pointer memori ekstensi Server Name Indication pada paket TLS Client Hello.
  * **`content:"instagram.com";`**: String nama domain yang dicocokkan (mencakup `www.instagram.com`, `api.instagram.com`, dll).
  * **`nocase;`**: Mengabaikan perbedaan huruf besar dan kecil.
  * **`classtype:policy-violation;`**: Klasifikasi pelanggaran kebijakan penggunaan internet organisasi.
  * **`sid:1000040;`**: Signature ID unik 1000040.
  * **`rev:1;`**: Revisi ke-1.

#### 2. Rule Deteksi Akses Facebook via TLS SNI:
```text
# Versi Lab VirtualBox (Rekomendasi Praktikum):
alert tls any any -> any 443 (msg:"[POLICY VIOLATION] Akses ke Facebook Terdeteksi via TLS SNI"; flow:established,to_server; tls.sni; content:"facebook.com"; nocase; classtype:policy-violation; sid:1000041; rev:2;)

# Versi Gateway/Router Enterprise:
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"[POLICY VIOLATION] Akses ke Facebook Terdeteksi via TLS SNI"; flow:established,to_server; tls.sni; content:"facebook.com"; nocase; classtype:policy-violation; sid:1000041; rev:2;)
```
* **Bedah Kata per Kata:**
  * **`alert`**: Aksi Mode IDS, catat insiden ke berkas log `fast.log`, izinkan paket tetap melintas ke peramban.
  * **`tls`**: Parser protokol lapisan aplikasi TLS/SSL Suricata.
  * **`any`** (Source IP): Alamat IP pengirim penyerang/penguji dari mana saja (mendukung IP Kali Linux `192.168.2.2`). Pada versi enterprise digunakan `$HOME_NET`.
  * **`any`** (Source Port): Nomor port klien peramban pengguna yang bersifat dinamis/acak.
  * **`->`** (*Direction Operator*): Arah aliran lalu lintas satu arah dari pengguna lokal keluar menuju server internet.
  * **`any`** (Destination IP): Alamat IP tujuan mana saja (mendukung IP server Ubuntu `192.168.2.3`). Pada versi enterprise digunakan `$EXTERNAL_NET`.
  * **`443`** (Destination Port): Nomor port baku protokol web terenkripsi HTTPS.
  * **`msg:"[POLICY VIOLATION] Akses ke Facebook Terdeteksi via TLS SNI"`**: Teks pesan peringatan deskriptif yang dicetak ke berkas log.
  * **`flow:established,to_server;`**:
    * `established`: Memastikan sesi jabat tangan koneksi TCP (*Three-Way Handshake*) telah berhasil terbentuk.
    * `to_server`: Hanya memeriksa paket permintaan yang keluar dari arah klien menuju server Facebook.
  * **`tls.sni;`**: *Sticky buffer*. Mengarahkan pencarian string secara spesifik hanya pada area memori ekstensi Server Name Indication pada paket TLS Client Hello yang masih berbentuk teks polos (*plaintext*).
  * **`content:"facebook.com";`**: String nama domain yang dicocokkan (mencakup `www.facebook.com`, `m.facebook.com`, `web.facebook.com`).
  * **`nocase;`**: Mengabaikan perbedaan huruf besar dan huruf kecil (*case-insensitive*).
  * **`classtype:policy-violation;`**: Klasifikasi kategori pelanggaran kebijakan penggunaan jaringan internal organisasi.
  * **`sid:1000041;`**: Signature ID unik 1000041.
  * **`rev:2;`**: Nomor versi revisi rule ke-2 (revisi kompatibilitas header lab).

### C. Solusi Layer 2: Deteksi via DNS Query Port 53 (Sebelum Koneksi Terbentuk)

Sebelum komputer pengguna dapat menghubungi server Instagram atau Facebook di port 443, peramban pengguna **wajib menanyakan alamat IP server tersebut ke server DNS** terlebih dahulu pada **Port 53 UDP**.

Suricata memiliki parser protokol **`dns`** dan sticky buffer **`dns.query`**.

#### 1. Rule Deteksi Pencarian DNS Instagram:
```text
alert dns $HOME_NET any -> any 53 (msg:"[POLICY VIOLATION] Query DNS untuk Domain Instagram Terdeteksi"; flow:to_server; dns.query; content:"instagram.com"; nocase; classtype:policy-violation; sid:1000043; rev:1;)
```
* **Bedah Kata per Kata:**
  * **`alert`**: Aksi Mode IDS, catat insiden pencarian domain ke berkas log tanpa membuang paket.
  * **`dns`**: Parser protokol lapisan aplikasi DNS (*Domain Name System*) pada Suricata.
  * **`$HOME_NET`** (Source IP): Komputer klien lokal yang mengajukan pertanyaan resolusi nama domain.
  * **`any`** (Source Port): Nomor port klien pengirim yang acak.
  * **`->`** (*Direction Operator*): Arah aliran lalu lintas satu arah dari klien menuju server DNS.
  * **`any`** (Destination IP): Menuju ke alamat IP server DNS mana saja (baik DNS internal kampus maupun DNS publik seperti 8.8.8.8, 1.1.1.1).
  * **`53`** (Destination Port): Nomor port baku layanan protokol DNS (Port 53 UDP/TCP).
  * **`msg:"[POLICY VIOLATION] Query DNS untuk Domain Instagram Terdeteksi"`**: Teks pesan peringatan di file log.
  * **`flow:to_server;`**: Memastikan arah paket adalah permintaan (*query*) yang dikirim dari klien menuju server DNS.
  * **`dns.query;`**: *Sticky buffer*. Mengarahkan pencarian string secara presisi pada field nama domain yang ditanyakan di dalam paket DNS (*Question Section*).
  * **`content:"instagram.com";`**: String nama domain yang dicari di dalam paket query DNS.
  * **`nocase;`**: Mengabaikan perbedaan huruf besar dan kecil.
  * **`classtype:policy-violation;`**: Klasifikasi pelanggaran kebijakan jaringan internal.
  * **`sid:1000043;`**: Signature ID unik 1000043.
  * **`rev:1;`**: Revisi ke-1.

#### 2. Rule Deteksi Pencarian DNS Facebook:
```text
# Versi Lab VirtualBox (Rekomendasi Praktikum):
alert dns any any -> any 53 (msg:"[POLICY VIOLATION] Query DNS untuk Domain Facebook Terdeteksi"; flow:to_server; dns.query; content:"facebook.com"; nocase; classtype:policy-violation; sid:1000044; rev:2;)

# Versi Gateway/Router Enterprise:
alert dns $HOME_NET any -> any 53 (msg:"[POLICY VIOLATION] Query DNS untuk Domain Facebook Terdeteksi"; flow:to_server; dns.query; content:"facebook.com"; nocase; classtype:policy-violation; sid:1000044; rev:2;)
```
* **Bedah Kata per Kata:**
  * **`alert`**: Aksi Mode IDS, catat kejadian ke log tanpa memutus query.
  * **`dns`**: Parser protokol aplikasi DNS Suricata.
  * **`any`** (Source IP): Klien lokal yang melakukan pencarian domain. Pada versi enterprise digunakan `$HOME_NET`.
  * **`any`** (Source Port): Port pengirim acak klien.
  * **`->`** (*Direction Operator*): Arah paket dari klien ke server DNS.
  * **`any`** (Destination IP): Server DNS tujuan mana saja di jaringan lokal atau internet.
  * **`53`** (Destination Port): Nomor port layanan DNS (Port 53).
  * **`msg:"[POLICY VIOLATION] Query DNS untuk Domain Facebook Terdeteksi"`**: Pesan alert di log.
  * **`flow:to_server;`**: Paket query DNS yang mengalir menuju server.
  * **`dns.query;`**: *Sticky buffer* penunjuk area nama domain yang ditanyakan klien.
  * **`content:"facebook.com";`**: Pola teks nama domain yang disaring.
  * **`nocase;`**: Case-insensitive untuk parameter content.
  * **`classtype:policy-violation;`**: Kategori pelanggaran kebijakan jaringan.
  * **`sid:1000044;`**: Signature ID unik 1000044.
  * **`rev:2;`**: Revisi ke-2 (revisi kompatibilitas header lab).
---

### D. Solusi Layer 3: Deteksi via HTTP Host Header Port 80

Jika pengguna mencoba mengetik alamat tanpa HTTPS (misal mengetik `http://facebook.com`), peramban mengirimkan paket HTTP GET polos ke port 80 sebelum dialihkan (*redirect*) ke HTTPS.

Suricata dapat mendeteksi header `Host:` menggunakan sticky buffer **`http.host`**:

```text
alert http any any -> any 80 (msg:"[POLICY VIOLATION] Akses HTTP Polos ke Facebook Terdeteksi"; flow:established,to_server; http.host; content:"facebook.com"; classtype:policy-violation; sid:1000045; rev:3;)
```
* **Bedah Kata per Kata:**
  * **`alert`**: Aksi Mode IDS, catat insiden ke log tanpa memutus koneksi peramban.
  * **`http`**: Parser protokol lapisan aplikasi HTTP Suricata.
  * **`any`** (Source IP): Alamat IP penyerang/penguji dari mana saja (mendukung IP Kali Linux `192.168.2.2`).
  * **`any`** (Source Port): Nomor port klien peramban yang dinamis.
  * **`->`** (*Direction Operator*): Arah paket satu arah menuju ke server.
  * **`any`** (Destination IP): Alamat IP tujuan mana saja (mendukung IP server Ubuntu `192.168.2.3`). Menggunakan `any -> any` sangat penting pada lab VirtualBox karena Ubuntu bukan gateway router Kali Linux.
  * **`80`** (Destination Port): Nomor port standar protokol web HTTP polos.
  * **`msg:"[POLICY VIOLATION] Akses HTTP Polos ke Facebook Terdeteksi"`**: Pesan peringatan alert di file log.
  * **`flow:established,to_server;`**:
    * `established`: Memastikan sesi TCP telah terjalin melalui Three-Way Handshake.
    * `to_server`: Memeriksa hanya paket request yang mengalir menuju server.
  * **`http.host;`**: *Sticky buffer*. Mengarahkan pencarian string khusus pada baris header `Host:` di dalam paket HTTP request (misal: `Host: facebook.com`).
  * **`content:"facebook.com";`**: Nama domain host yang dituju dalam huruf kecil murni. *(Catatan Suricata 7.x: Jangan menambahkan `nocase;` pada buffer `http.host` karena buffer hostname sudah dinormalisasi otomatis ke huruf kecil oleh engine. Menambahkan `nocase;` akan ditolak oleh parser Suricata 7 sebagai galat error parsing signature)*.
  * **`classtype:policy-violation;`**: Klasifikasi pelanggaran kebijakan jaringan internal.
  * **`sid:1000045;`**: Signature ID unik 1000045.
  * **`rev:3;`**: Revisi ke-3 (revisi penggunaan `any -> any` untuk kompatibilitas topologi lab VirtualBox).
---

### E. Aturan Mode IPS: Pemblokiran Akses Media Sosial (Action Drop)

Jika dosen meminta agar akses ke Instagram **langsung diblokir dan tidak boleh terbuka sama sekali**, ubah aksinya menjadi **`drop`** pada mode IPS inline:

```text
drop tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"[BLOCKED] Akses ke Instagram Diblokir oleh IPS via TLS SNI"; flow:established,to_server; tls.sni; content:"instagram.com"; nocase; classtype:policy-violation; sid:1000042; rev:1;)
* **Bedah Kata per Kata:**
  * **`drop`**: **Aksi Pencegahan Mode IPS**. Memerintahkan kernel Linux via antrean NFQUEUE untuk seketika memusnahkan (*drop/discard*) paket TLS Client Hello yang membawa domain Instagram. Paket dibuang di memori kernel, peramban klien langsung macet (*Connection Timed Out*), dan koneksi gagal terbentuk.
  * **`tls`**: Parser protokol lapisan aplikasi TLS/SSL Suricata.
  * **`$HOME_NET`** (Source IP): Komputer pengguna lokal yang mencoba membuka Instagram.
  * **`any`** (Source Port): Nomor port klien peramban pengguna.
  * **`->`** (*Direction Operator*): Arah lalu lintas paket keluar dari pengguna lokal menuju server luar.
  * **`$EXTERNAL_NET`** (Destination IP): Server milik Meta/Instagram di internet publik.
  * **`443`** (Destination Port): Port standar protokol web terenkripsi HTTPS.
  * **`msg:"[BLOCKED] Akses ke Instagram Diblokir oleh IPS via TLS SNI"`**: Teks pesan pemblokiran yang dicatat ke `fast.log` dengan label `[Drop]`.
  * **`flow:established,to_server;`**:
    * `established`: Memastikan jabat tangan TCP telah selesai.
    * `to_server`: Hanya memeriksa paket permintaan yang keluar dari klien menuju server luar.
  * **`tls.sni;`**: *Sticky buffer*. Mengarahkan pencarian string pada ekstensi Server Name Indication pada paket TLS Client Hello.
  * **`content:"instagram.com";`**: String domain sasaran yang diblokir.
  * **`nocase;`**: Mengabaikan perbedaan huruf besar dan kecil.
  * **`classtype:policy-violation;`**: Klasifikasi pelanggaran kebijakan jaringan.
  * **`sid:1000042;`**: Signature ID unik 1000042.
  * **`rev:1;`**: Revisi ke-1.
* **Dampak Teknis:**
  Peramban pengguna seketika macet dan menampilkan pesan galat:
  > *"Secure Connection Failed / The connection has timed out"*
---

### F. Mengapa Mengetik "facebook.com" di Firefox Kali Linux Tidak Menghasilkan Alert?

Ketika kamu membuka Firefox di Kali Linux lalu mengetik `facebook.com`, alert **tidak akan pernah muncul** di Ubuntu jika kamu belum memahami konsep perutean jaringan (*network routing*):

#### Dua Penyebab Teknisnya:
1. **Perutean Interface VirtualBox (Bypass Jaringan):**
   * Kali Linux memiliki 2 adapter: Adapter 1 (NAT / Internet) dan Adapter 2 (Host-Only `192.168.2.x`).
   * Saat kamu membuka `facebook.com` di Firefox, sistem operasi Kali Linux merutekan paket tersebut keluar melalui **Adapter 1 (NAT) langsung ke internet publik asli**.
   * Paket tersebut **SAMA SEKALI TIDAK MELEWATI** kabel jaringan virtual `enp0s8` milik Ubuntu tempat Suricata menyadap! Suricata pada Ubuntu menerima nol byte paket.
2. **Perbedaan Arah Header Rule (`$HOME_NET` vs `$EXTERNAL_NET`):**
   * Pada rule enterprise: `$HOME_NET any -> $EXTERNAL_NET 80` dirancang untuk Suricata yang dipasang pada Router/Gateway perusahaan (di mana seluruh trafik karyawan internal wajib menyeberang router untuk menuju internet).
   * Pada lab VirtualBox, Ubuntu bukanlah router gateway Kali Linux. Jika Kali mengirim paket ke Ubuntu (`192.168.2.2 -> 192.168.2.3`), Kali adalah Source dan Ubuntu adalah Destination. Maka header rule wajib menggunakan `any any -> any 80`.

---

### G. Dua Cara Praktik Menguji Rule Facebook di Lab (100% Berhasil)

#### Cara 1: Menggunakan cURL dengan Header Host Palsu (Paling Cepat & Elegan)
Di terminal Kali Linux, tembakkan request langsung ke IP Ubuntu (`192.168.2.3`) namun sisipkan header `Host: facebook.com`:
```bash
curl -i -H "Host: facebook.com" http://192.168.2.3/
```
* **Bedah Perintah:**
  * **`curl`**: Alat pengirim paket HTTP CLI.
  * **`-i`**: Menampilkan response header server.
  * **`-H "Host: facebook.com"`**: Menyuntikkan baris header HTTP kustom `Host: facebook.com` ke dalam paket request.
  * **`http://192.168.2.3/`**: Mengarahkan paket melewati kartu jaringan `enp0s8` langsung ke server Ubuntu tempat Suricata menyadap.
* **Hasil di Terminal Ubuntu:**
  Suricata membaca buffer `http.host`, menemukan string `facebook.com`, dan seketika mencetak alert di `fast.log`:
  ```text
  [**] [1:1000045:3] [POLICY VIOLATION] Akses HTTP Polos ke Facebook Terdeteksi [**] [Priority: 1] {TCP} 192.168.2.2:xxxx -> 192.168.2.3:80
  ```

#### Cara 2: Membelokkan DNS Facebook ke IP Ubuntu via `/etc/hosts` di Kali Linux
Jika ingin membuktikan secara visual langsung menggunakan peramban **Mozilla Firefox** di Kali Linux:

1. Di terminal Kali Linux, buka berkas pemetaan domain lokal:
   ```bash
   sudo nano /etc/hosts
   ```
2. Tambahkan satu baris di paling bawah:
   ```text
   192.168.2.3 facebook.com www.facebook.com
   ```
3. Simpan: `Ctrl + O` $\rightarrow$ `Enter` $\rightarrow$ `Ctrl + X`.
4. Buka peramban Firefox di Kali Linux, ketik di bilah alamat:
   ```text
   http://facebook.com
   ```
   *(Wajib ketik dengan awalan `http://`, bukan `https://`)*.
5. Firefox di Kali Linux akan menyelesaikan nama `facebook.com` ke IP `192.168.2.3` dan mengirimkan paket HTTP port 80 melewati kartu jaringan `enp0s8`.
6. Periksa terminal Ubuntu (`sudo tail -f /var/log/suricata/fast.log`), alert `[1:1000045:3]` akan langsung terpicu seketika di layar!
*(Setelah selesai demonstrasi, hapus kembali baris tersebut dari `/etc/hosts`)*.

---

## 14. TEORI & ANALISIS KOMPARATIF 3 SERANGAN WEB: SQLi, XSS, DAN CSRF

Dalam ranah keamanan aplikasi web (*OWASP Top 10*), SQL Injection (SQLi), Cross-Site Scripting (XSS), dan Cross-Site Request Forgery (CSRF) adalah tiga kelas kerentanan paling mendasar dengan karakteristik, target, dan mekanisme kerja yang sangat berbeda.

---

### A. SQL Injection (SQLi) - Konsep, Lokasi Eksekusi, dan Dampak

1. **Definisi:**
   Kerentanan di mana penyerang menyisipkan perintah SQL ilegal (*malicious SQL statements*) ke dalam formulir input atau parameter URL aplikasi web yang tidak disanitasi dengan benar, sehingga mesin database mengeksekusi instruksi tersebut di luar niat awal pengembang.
2. **Akar Masalah (*Root Cause*):**
   Percampuran antara **Data (input pengguna)** dan **Kode (instruksi query SQL)** dalam satu string kueri yang sama. Mesin parser database tidak mampu membedakan mana batas akhir data masukan pengguna dan mana instruksi tambahan dari penyerang.
   * *Contoh Kode Rentan di DVWA:*
     ```php
     $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
     ```
3. **Lokasi Eksekusi (*Execution Environment*):**
   **SISI SERVER (Database Engine MariaDB / MySQL).**  
   Peramban pengguna hanya bertindak sebagai media pengirim; seluruh proses kompilasi kueri dan manipulasi tabel terjadi di dalam CPU dan memori server basis data.
4. **Target Serangan:**
   Struktur basis data, tabel sensitif (`users`), kredensial akun, data pribadi pengguna, serta integritas data backend.
5. **Dampak terhadap Triad CIA:**
   * **Confidentiality (Kerahasiaan):** Rusak total (penyerang dapat mengekstrak seluruh isi database via teknik `UNION SELECT` atau Tautologi boolean `' OR '1'='1`).
   * **Integrity (Integritas):** Rusak (penyerang dapat memodifikasi nilai saldo, mengubah role hak akses, atau menghapus tabel via `DROP TABLE`).
   * **Availability (Ketersediaan):** Rusak (penyerang dapat menyuntikkan fungsi `BENCHMARK()` atau `SLEEP()` berulang-ulang untuk menghabiskan CPU database).

---

### B. Cross-Site Scripting (XSS) - Konsep, Lokasi Eksekusi, dan Dampak

1. **Definisi:**
   Kerentanan di mana penyerang menyuntikkan skrip kode berbahaya (biasanya bahasa JavaScript) ke dalam halaman web yang sah, sehingga skrip tersebut dieksekusi secara otomatis oleh **peramban (*browser*) milik korban/pengguna lain** yang sedang membuka halaman tersebut.
2. **Akar Masalah (*Root Cause*):**
   Aplikasi web menampilkan kembali data yang dimasukkan pengguna ke dalam dokumen HTML tanpa melakukan penyaringan (*sanitization*) atau pengubahan karakter khusus (*context-aware HTML output encoding* seperti `htmlspecialchars`).
   * *Contoh Kode Rentan di DVWA:*
     ```php
     echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
     ```
3. **Lokasi Eksekusi (*Execution Environment*):**
   **SISI KLIEN (Peramban / Browser Korban).**  
   Server web hanya bertindak sebagai media penyimpan atau pemantul (*reflector*). Kode JavaScript penyerang dieksekusi oleh mesin JavaScript peramban korban (V8 di Chrome atau SpiderMonkey di Firefox).
4. **Target Serangan:**
   Sesi autentikasi korban, cookie sesi rahasia (`PHPSESSID`), token penyimpanan lokal (*LocalStorage / SessionStorage*), kredensial login, dan antarmuka visual peramban (*DOM Defacement*).
5. **Tiga Varian Utama XSS:**
   * **Reflected XSS (Non-Persistent):** Skrip jahat disuntikkan via link URL query parameter dan langsung dipantulkan kembali oleh server dalam satu siklus request-response (contoh: video dosen `XSS.mkv`).
   * **Stored XSS (Persistent):** Skrip jahat disimpan secara permanen di database server (misal kolom komentar buku tamu / forum), dan akan mengeksekusi di peramban setiap orang yang membuka halaman tersebut.
   * **DOM-Based XSS:** Kerentanan terjadi murni di sisi script JavaScript klien yang memproses data dari sumber yang tidak aman (*source* seperti `document.location`) dan menuliskannya ke objek DOM berbahaya (*sink* seperti `document.write` atau `element.innerHTML`) tanpa menyentuh backend server.

---

### C. Cross-Site Request Forgery (CSRF / XSRF) - Konsep, Lokasi Eksekusi, dan Dampak

1. **Definisi:**
   Serangan di mana penyerang memperdaya atau memanipulasi peramban korban yang sedang dalam keadaan terautentikasi (memiliki sesi login aktif di sebuah situs) untuk mengirimkan permintaan HTTP berbahaya (*unauthorized request*) ke situs tersebut tanpa disadari atau dikehendaki oleh korban.
2. **Akar Masalah (*Root Cause*):**
   Aplikasi web **sepenuhnya mempercayai peramban korban** hanya berdasarkan kehadiran cookie sesi (`Cookie: PHPSESSID=...`). Peramban secara otomatis melampirkan cookie sesi pada setiap request yang mengarah ke domain sasaran, bahkan jika request tersebut dipicu oleh situs pihak ketiga yang jahat.
   * *Syarat Mutlak Berfungsinya CSRF:*
     1. Korban harus sedang memiliki sesi login aktif di aplikasi target.
     2. Permintaan perubahan data (seperti ganti password) tidak memiliki validasi parameter rahasia yang tidak dapat ditebak (*Anti-CSRF Token*).
3. **Skenario Praktis: CSRF itu Sebenarnya Kayak Gimana? (Analogi Nyata):**
   * Bayangkan kamu baru saja selesai login ke akun bank kamu di situs `bankku.com`. Sesi loginmu masih aktif di peramban (cookie bank tersimpan).
   * Tanpa menutup peramban, di tab sebelah kamu membuka link kiriman orang tak dikenal atau situs nonton film gratis `nonton-gratis.xyz`.
   * Di dalam website `nonton-gratis.xyz` tersebut, penyerang telah menyelipkan kode tersembunyi yang menyuruh perambanmu memanggil:
     `https://bankku.com/transfer?tujuan=rekening_penyerang&jumlah=10000000`
   * Karena perambanmu sedang memanggil domain `bankku.com`, peramban **secara otomatis dan tanpa bertanya** melampirkan cookie sesi login bankmu yang sah.
   * Server `bankku.com` menerima request tersebut dan memeriksa: *"Ada cookie sesi sah milik Afif, berarti request ini asli dari Afif!"*
   * **Hasil:** Uang 10 juta rupiah terkirim ke rekening penyerang tanpa kamu pernah membuka halaman transfer bank dan tanpa kamu pernah mengklik tombol konfirmasi!

4. **Lewat Mana Serangan CSRF Masuk? (Apakah Lewat URL atau Textform?):**
   Berbeda dengan XSS yang biasanya dimasukkan lewat *textform* (kolom input nama, kolom komentar, atau kolom pencarian) di dalam website target, **CSRF MASUK DARI LUAR APLIKASI MELALUI TIGA VEKTOR UTAMA**:

   * **Vektor 1: Lewat URL / Link Terbuka (Untuk Aplikasi Berbasis Metode HTTP GET — Seperti di DVWA):**
     Jika aplikasi memproses aksi perubahan data menggunakan metode GET (seperti form ganti password DVWA), penyerang bisa melancarkannya lewat:
     * **Tautan Phishing (Social Engineering):** Penyerang mengirim pesan chat: *"Lihat promo ini!"* yang berisi link langsung:
       `http://192.168.2.3/dvwa/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change`
       Ketika korban (yang sedang login DVWA) mengklik link tersebut, peramban membuka tab baru dan seketika password DVWA korban terganti!
     * **Tag Gambar Tersembunyi (Zero-Click Exploit):** Penyerang menyisipkan tag gambar di situs web miliknya atau di forum publik:
       ```html
       <img src="http://192.168.2.3/dvwa/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change" width="0" height="0" style="display:none;">
       ```
       Ketika korban membuka halaman tersebut, peramban mengira itu file gambar dan otomatis melakukan request GET ke URL tersebut. Password korban terganti tanpa perlu mengklik tautan apa pun!

   * **Vektor 2: Lewat Formulir Tersembunyi Otomatis (Untuk Aplikasi Berbasis Metode HTTP POST):**
     Banyak pengembang mengira: *"Kalau ganti password pakai metode POST, pasti kebal CSRF!"* Anggapan ini **100% SALAH**.
     Penyerang membuat halaman web jebakan di server miliknya (misal `evil.com/hadiah.html`) yang memuat form tersembunyi yang di-submit otomatis oleh JavaScript:
     ```html
     <form id="stolenForm" action="http://192.168.2.3/dvwa/vulnerabilities/csrf/" method="POST">
         <input type="hidden" name="password_new" value="hacked123">
         <input type="hidden" name="password_conf" value="hacked123">
         <input type="hidden" name="Change" value="Change">
     </form>
     <script>
         // Otomatis terkirim saat halaman dibuka korban!
         document.getElementById('stolenForm').submit();
     </script>
     ```
     Begitu korban mengunjungi `evil.com`, peramban korban dipaksa mengirimkan paket HTTP POST ke DVWA membawa cookie sesi aktif korban.

   * **Vektor 3: Lewat Injeksi Skrip XSS (Chained Exploit — Video Dosen `CSRF.mkv`):**
     Jika aplikasi memasang proteksi token rahasia (*Anti-CSRF Token / `user_token`*) seperti DVWA level High, serangan link luar di atas akan gagal. Penyerang membobolnya dengan mengeksploitasi celah XSS terlebih dahulu untuk mencuri token dari DOM peramban, lalu menembakkan request CSRF yang valid dari dalam.

5. **Lokasi Eksekusi (*Execution Environment*):**
   **SISI KLIEN MEMICU AKSI KE SISI SERVER.**  
   Peramban korban dieksploitasi sebagai "senjata perantara (*confused deputy*)" untuk mengirimkan request pengubahan data yang sah di mata server target.
6. **Target Serangan:**
   Fungsi dan logika bisnis aplikasi web yang mengubah status (*state-changing requests*): mengganti kata sandi akun, mengubah alamat email pemulihan, mentransfer dana perbankan, atau memodifikasi izin administratif.
7. **Dampak terhadap Triad CIA:**
   * **Integrity (Integritas):** Rusak parah (status akun atau data korban diubah paksa atas nama korban tanpa persetujuannya).
   * *Catatan Penting:* CSRF standar **tidak dapat membaca respon data server** (*blind attack*) akibat kebijakan *Same-Origin Policy (SOP)* peramban, sehingga CSRF murni berfokus pada perusakan integritas data, bukan pencurian data.
---

### D. Tabel Matriks Perbandingan Pembeda Utama (SQLi vs XSS vs CSRF)

| Parameter Komparasi | SQL Injection (SQLi) | Cross-Site Scripting (XSS) | Cross-Site Request Forgery (CSRF) |
|---|---|---|---|
| **Lokasi Eksekusi Kode** | **Sisi Server** (Database Engine) | **Sisi Klien** (Peramban Korban) | **Sisi Klien menembak Server Target** |
| **Siapa Korban Utamanya?** | **Server / Basis Data Organisasi** | **Pengguna Lain / Klien Peramban** | **Integritas Akun Pengguna Terautentikasi** |
| **Prinsip Kepercayaan yang Dilanggar** | Server mempercayai input mentah pengguna sebagai perintah SQL. | Peramban mempercayai seluruh skrip yang dikirimkan oleh server web. | Server mempercayai request pengguna hanya berdasarkan cookie sesi otomatis. |
| **Bahasa Payload** | Sintaks SQL (`SELECT`, `UNION`, `' OR '1'='1`) | Sintaks HTML / JavaScript (`<script>`, `onerror=`) | HTTP Request Manipulation (`<img>`, `<form>`, link jebakan) |
| **Kemampuan Membaca Data** | **BISA** (Membocorkan isi database langsung). | **BISA** (Mencuri cookie sesi dan token DOM). | **TIDAK BISA** (Hanya mengirim aksi perubahan status / *Blind Action*). |
| **Kebutuhan Sesi Login** | **TIDAK PERLU** (Bisa diserang secara anonim). | **TIDAK PERLU** (Bisa disuntikkan secara anonim). | **WAJIB LOGIN** (Hanya berhasil jika korban sedang terautentikasi). |
| **Target Celah di DVWA** | Form pencarian ID (`/vulnerabilities/sqli/`) | Form input nama (`/vulnerabilities/xss_r/`) | Form ganti password (`/vulnerabilities/csrf/`) |

---

### E. Analisis Eksploitasi Berantai (Chained Attack XSS ke CSRF pada Video Dosen)

Dalam materi video dosen `CSRF.mkv`, dosen mendemonstrasikan bahwa pada tingkat keamanan **High**, aplikasi web DVWA memasang proteksi **Anti-CSRF Token (`user_token`)** pada form pergantian kata sandi.  
Token ini dibuat secara dinamis di server dan diselipkan di dalam kode HTML, sehingga penyerang dari luar tidak dapat menebak nilainya untuk melancarkan serangan CSRF biasa.

#### Bagaimana Dosen Menembusnya? (*Exploit Chaining*):
Dosen menggabungkan dua kerentanan secara berurutan:

```text
[Attacker Link]
      │
      ▼
1. Celah DOM XSS (/vulnerabilities/xss_d/)
      │ (Eksekusi script eksternal: exp.js di browser korban)
      ▼
2. Skrip exp.js membaca memori DOM halaman (/vulnerabilities/csrf/)
      │ (Mencuri nilai rahasia: user_token milik admin secara legal)
      ▼
3. Skrip exp.js memicu request pergantian password
      │ (GET /vulnerabilities/csrf/?password_new=admin123&user_token=[TOKEN_CURIAN])
      ▼
4. Server DVWA memverifikasi token -> Status 200 OK -> Password Berhasil Diubah!
```
* **Kesimpulan Analitis:** Kerentanan XSS dapat digunakan sebagai jembatan pembuka (*enabler*) untuk meruntuhkan pertahanan anti-CSRF token yang paling ketat sekalipun.

---

### F. Strategi Pertahanan & Mitigasi Resmi Masing-Masing Kerentanan

Jika dosen bertanya: *"Bagaimana cara developer memperbaiki source code agar kebal dari masing-masing serangan tersebut?"*

1. **Mitigasi Mutlak SQL Injection:**
   * **Gunakan *Prepared Statements / Parameterized Queries*:** Memisahkan secara tegas antara struktur instruksi SQL dan nilai data masukan (menggunakan pustaka PDO atau MySQLi bind_param).
     ```php
     $stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
     $stmt->execute(['id' => $id]);
     ```
   * Terapkan prinsip hak akses terendah (*Least Privilege*) pada akun pengguna database.

2. **Mitigasi Mutlak Cross-Site Scripting (XSS):**
   * **Gunakan *Context-Aware Output Encoding*:** Seluruh data yang berasal dari pengguna wajib diubah karakter khususnya sebelum dicetak ke layar peramban.
     ```php
     echo '<pre>Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</pre>';
     ```
   * Pasang header keamanan HTTP **`Content-Security-Policy (CSP)`** untuk membatasi domain asal skrip JavaScript yang diizinkan dieksekusi.
   * Pasang atribut **`HttpOnly`** pada cookie sesi agar cookie tidak bisa dibaca oleh JavaScript via `document.cookie`.

3. **Mitigasi Mutlak Cross-Site Request Forgery (CSRF):**
   * **Terapkan *Anti-CSRF Token (Synchronizer Token Pattern)*:** Setiap formulir perubahan data wajib menyertakan token acak kriptografis yang diverifikasi keabsahannya oleh server sebelum memproses request.
   * **Gunakan Atribut Cookie `SameSite`:** Setel bendera cookie sesi menjadi `SameSite=Strict` atau `SameSite=Lax` agar peramban menolak mengirimkan cookie sesi secara otomatis pada request yang berasal dari domain pihak ketiga.
   * **Wajibkan Re-Autentikasi (Password Lama):** Untuk tindakan sensitif (seperti ganti password atau ubah nomor rekening), wajibkan pengguna memasukkan kembali kata sandi lama mereka.

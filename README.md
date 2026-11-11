# REKAP LENGKAP PRAKTIKUM KEAMANAN JARINGAN (KAMJAR)
**Materi:** IDS/IPS Suricata, Web Application Security (DVWA), & Attack Simulation  
**Penulis:** Afif Nur Rahman (H1H024016)  
**Target Lab:** Universitas Jenderal Soedirman  

---

## DAFTAR ISI
1. [Bedah Perintah Terminal VM 1 (Kali Linux - Attacker) Kata per Kata](#1-bedah-perintah-terminal-vm-1-kali-linux---attacker)
2. [Bedah Perintah Terminal VM 2 (Ubuntu Server - Defender) Kata per Kata](#2-bedah-perintah-terminal-vm-2-ubuntu-server---defender)
3. [Bedah Total Komponen Rules Suricata (Header & Options)](#3-bedah-total-komponen-rules-suricata)
4. [Bedah Seluruh Baris Rules Praktikum Kata per Kata](#4-bedah-seluruh-baris-rules-praktikum)
   - [Rule A: SYN Flood (Bab V Modul - sid:1000001)](#rule-a-syn-flood-bab-v-modul---sid1000001)
   - [Rule B: ICMP Burst (Bab V Modul - sid:1000002)](#rule-b-icmp-burst-bab-v-modul---sid1000002)
   - [Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)](#rule-c-udp-burst-port-53-dns-bab-v-modul---sid1000003)
   - [Rule 1: SQL Injection Tautology Bypass (sid:1000021)](#rule-1-sql-injection-tautology-bypass---sid1000021)
   - [Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)](#rule-2-reflected-xss-event-handler-bypass---sid1000022)
   - [Rule 3: CSRF Unauthorized Password Change (sid:1000023)](#rule-3-csrf-unauthorized-password-change---sid1000023)
   - [Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)](#rule-4-dos-tcp-syn-flood-port-80-dvwa---sid1000024)
   - [Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)](#rule-5-mode-ips---sql-injection-dropped---sid1000021-rev5)
5. [Konseptual Arsitektur: Mode IDS vs Mode IPS](#5-konseptual-arsitektur-mode-ids-vs-mode-ips)

---

## 1. BEDAH PERINTAH TERMINAL VM 1 (KALI LINUX - ATTACKER)

### A. Perintah DoS TCP SYN Flood Terukur
```bash
sudo hping3 -S -p 80 -c 50 --faster 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Menjalankan perintah dengan hak akses root/administrator tertinggi. Wajib digunakan karena perakitan paket mentah (*raw socket creation*) memerlukan izin langsung ke kernel Linux.
* **`hping3`**: Program generator dan penganalisis paket jaringan berbasis CLI yang mampu menyusun header TCP/IP kustom.
* **`-S`** (*SYN Flag*): Mengaktifkan bendera TCP **SYN** (*Synchronize*), yaitu paket inisiasi awal koneksi pada *TCP Three-Way Handshake*.
* **`-p 80`** (*Port destination*): Mengarahkan paket serangan tepat ke port 80 (port layanan web HTTP Apache / DVWA).
* **`-c 50`** (*Count 50*): Membatasi jumlah paket yang dikirimkan tepat sebanyak 50 paket, lalu proses berhenti secara otomatis agar server lab tidak hang.
* **`--faster`** (*Fast rate*): Mengatur kecepatan pengiriman paket dengan interval 10 milidetik, atau setara dengan **100 paket per detik**. Laju ini menjamin ambang batas Suricata terpicu seketika.
* **`192.168.2.3`**: Alamat IP mesin target/korban (VM Ubuntu Server).

### B. Perintah DoS Mode Flood Ekstrem
```bash
sudo hping3 -S -p 80 --flood 192.168.2.3
```
* **`--flood`**: Mengirimkan paket secepat mungkin sesuai kapasitas maksimal bandwidth antarmuka tanpa memproses paket balasan (*no reply listening*). Mode ini membanjiri buffer terminal sehingga perlu dihentikan paksa.

### C. Perintah Menghentikan Paksa Proses Macet
```bash
sudo killall -9 hping3
```
* **`killall`**: Utilitas untuk mengirimkan sinyal penghentian ke seluruh proses berdasarkan nama aplikasinya.
* **`-9`** (*SIGKILL*): Sinyal pembunuhan mutlak di kernel Linux. Sinyal ini tidak bisa diabaikan atau ditahan oleh aplikasi yang hang.
* **`hping3`**: Nama proses yang dihentikan.

### D. Perintah Pengujian ICMP Ping
```bash
ping -c 3 192.168.2.3
```
* **`ping`**: Utilitas penguji konektivitas berbasis protokol ICMP.
* **`-c 3`** (*Count 3*): Mengirimkan tepat 3 paket *ICMP Echo Request*.
* **`192.168.2.3`**: Alamat IP target.

### E. Perintah Eksploitasi Web via CLI
```bash
curl -i -s "http://192.168.2.3/dvwa/vulnerabilities/sqli/?id=%27+OR+%271%27%3D%271&Submit=Submit"
```
* **`curl`** (*Client URL*): Alat CLI untuk mentransfer data melalui protokol HTTP/HTTPS.
* **`-i`** (*Include Headers*): Menampilkan response header HTTP dari server (`HTTP/1.1 200 OK`, `Set-Cookie`, dll) bersamaan dengan konten body.
* **`-s`** (*Silent*): Menyembunyikan progress meter agar tampilan terminal bersih.
* **`"..."`**: URL endpoint yang disisipi payload. Tanda petik dua wajib dipasang agar karakter `&`, `?`, `=`, `'` tidak dieksekusi sebagai operator shell Linux.

---

## 2. BEDAH PERINTAH TERMINAL VM 2 (UBUNTU SERVER - DEFENDER)

### A. Validasi Sintaks Konfigurasi Suricata
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
* **`sudo`**: Hak akses root.
* **`suricata`**: Biner mesin IDS/IPS Suricata.
* **`-T`** (*Test configuration*): Menjalankan Suricata dalam mode uji coba sintaks. Suricata akan mengompilasi konfigurasi dan seluruh rules ke memori, memastikan tidak ada galat (error kurung/spasi/variabel), lalu langsung keluar tanpa sniffing.
* **`-c`** (*Config file path*): Menentukan jalur berkas konfigurasi utama.
* **`/etc/suricata/suricata.yaml`**: Jalur file konfigurasi master Suricata.
* **`-v`** (*Verbose*): Menampilkan log inisialisasi detail langkah demi langkah ke layar terminal.

### B. Live Reload Rules Tanpa Restart Layanan
```bash
sudo suricatasc -c reload-rules
```
* **`suricatasc`** (*Suricata Socket Client*): Utilitas CLI untuk berinteraksi langsung dengan daemon Suricata yang berjalan melalui UNIX domain socket (`suricata-command.socket`).
* **`-c`** (*Command*): Memberikan instruksi spesifik ke socket Suricata.
* **`reload-rules`**: Perintah agar Suricata membaca ulang file `.rules` dan menukarnya secara atomik di memori (*zero packet loss*).

### C. Live Monitoring Log Alert
```bash
sudo tail -f /var/log/suricata/fast.log
```
* **`tail`**: Menampilkan baris terakhir dari sebuah berkas teks.
* **`-f`** (*Follow mode*): Mengunci terminal dalam status mendengarkan (*listen*). Setiap kali Suricata menulis baris peringatan serangan baru, terminal langsung menampilkannya secara real-time.
* **`/var/log/suricata/fast.log`**: Berkas teks tempat Suricata mencatat alert ringkas satu baris.

### D. Manajemen Service Systemd
```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```
* **`systemctl`**: Utilitas pengendali sistem inisialisasi dan manajer layanan (*systemd*).
* **`restart`**: Menghentikan proses dan menyalakannya kembali dari nol.
* **`status`**: Memeriksa status kesehatan layanan (apakah aktif hijau, PID proses, dan histori log).

### E. Inspeksi Antarmuka Jaringan
```bash
ip -br a
```
* **`ip`**: Utilitas modern jaringan Linux (pengganti `ifconfig`).
* **`-br`** (*Brief*): Menampilkan data dalam format tabel satu baris ringkas per kartu jaringan.
* **`a`** (*Address*): Menampilkan informasi alamat IP yang terpasang pada antarmuka.

### F. Mode IPS Menggunakan Iptables & NFQUEUE
```bash
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -v
```
* **`iptables`**: Program firewall bawaan kernel Linux untuk menyaring paket data.
* **`-I INPUT`** (*Insert to INPUT chain*): Menyisipkan aturan pada urutan paling awal pada rantai *INPUT* (paket yang masuk menuju server lokal).
* **`-p tcp`** (*Protocol TCP*): Aturan hanya berlaku untuk protokol TCP.
* **`--dport 80`** (*Destination Port 80*): Mengunci paket yang tujuannya ke port web 80.
* **`-j NFQUEUE`** (*Jump to Netfilter Queue*): Aksi target. Paket tidak langsung diberikan ke Apache, melainkan dialihkan ke antrean memori kernel *NFQUEUE*.
* **`--queue-num 0`**: Nomor antrean memori yang digunakan (antrean nomor 0).
* **`-q 0`** (*Queue 0 pada Suricata*): Memerintahkan Suricata untuk bertindak sebagai worker IPS yang menginspeksi antrean nomor 0. Paket aman akan diberi vonis `NF_ACCEPT`, paket jahat diberi vonis `NF_DROP`.

---

## 3. BEDAH TOTAL KOMPONEN RULES SURICATA

Setiap rule Suricata terbagi menjadi dua bagian besar:
$$\text{RULE} = \mathbf{HEADER} + \mathbf{OPTIONS}$$

```text
[action] [protocol] [src_ip] [src_port] [direction] [dst_ip] [dst_port] ( [rule_options] )
```

### A. Komponen Rule Header (Di Luar Tanda Kurung)
1. **Action (`alert` / `drop` / `reject` / `pass`):**
   * `alert`: Catat peringatan ke log, izinkan paket lewat (Mode IDS).
   * `drop`: Buang paket seketika tanpa balasan ke penyerang (Mode IPS).
   * `reject`: Buang paket dan kirim sinyal putus TCP RST / ICMP Unreachable ke penyerang (Mode IPS).
   * `pass`: Lewatkan paket dan abaikan seluruh rule lain (whitelist).
2. **Protocol (`http`, `tcp`, `udp`, `icmp`, `ip`):**
   * Menentukan parser protokol lapisan transport/aplikasi yang akan memproses paket.
3. **Source IP & Source Port (`any any`):**
   * Menentukan alamat IP dan port pengirim. Nilai `any any` berarti Suricata memeriksa paket dari alamat IP dan port berapa pun (karena port penyerang bersifat acak/ephemeral).
4. **Direction Operator (`->`):**
   * Menandakan arah lalu lintas data. `->` berarti satu arah (dari kiri ke kanan / dari sumber ke tujuan). `<>` berarti dua arah bolak-balik.
5. **Destination IP (`$HOME_NET`):**
   * Variabel yang didefinisikan pada `suricata.yaml` untuk mewakili jaringan atau server target yang dilindungi (contoh: `192.168.2.3/32`).
6. **Destination Port (`80`, `53`, `any`):**
   * Port tujuan layanan target. `80` untuk HTTP web server, `53` untuk DNS server, `any` untuk sembarang port.

### B. Komponen Rule Options (Di Dalam Tanda Kurung)
1. **`msg:"...";`**: Teks deskriptif yang akan dicetak pada file log saat serangan terdeteksi.
2. **`flow:established,to_server;`**: Memastikan TCP Three-Way Handshake telah selesai sempurna dan arah paket bergerak dari klien menuju server.
3. **`http.uri;`**: *Sticky buffer* yang menginstruksikan engine Suricata untuk hanya memeriksa URL path dan query string, bukan memeriksa header atau body.
4. **`content:"...";`**: Pola teks (*string literal*) yang dicari di dalam payload paket.
5. **`nocase;`**: *Case-insensitive modifier*. Mengabaikan huruf besar dan huruf kecil (misal `OR`, `or`, `Or` dianggap sama).
6. **`distance:0;`**: Pengatur jarak relatif. Menentukan bahwa pencarian pola teks kedua harus dimulai tepat setelah pola teks pertama ditemukan.
7. **`pcre:"/.../flags";`**: *Perl-Compatible Regular Expression* untuk pencarian pola kompleks tingkat lanjut.
8. **`flags:S;` atau `flags:S,12;`**: Memeriksa bendera TCP pada header. `S` adalah SYN flag. Angka `,12` berarti mengabaikan bit ECN (*Explicit Congestion Notification*) bits 1 dan 2.
9. **`itype:8;`**: Memeriksa tipe paket ICMP. Angka 8 adalah *ICMP Echo Request* (permintaan ping).
10. **`threshold:...;`**: Mesin pembatas laju trafik untuk mencegah banjir log.
    * `type threshold`: Memberi alert setiap kali batas count tercapai.
    * `type both`: Memberi alert sekali saat count tercapai, lalu menahan alert selama rentang waktu detik yang ditentukan.
    * `track by_src`: Menghitung laju berdasarkan alamat IP penyerang tunggal.
    * `count X, seconds Y`: Ambang batas X kejadian dalam kurun waktu Y detik.
11. **`classtype:...;`**: Klasifikasi kategori serangan yang otomatis memetakan tingkat keparahan (*Priority*) pada sistem.
12. **`sid:...;`**: *Signature ID* unik. Nomor di atas 1.000.000 dicadangkan khusus untuk rule lokal pengguna.
13. **`rev:...;`**: Nomor versi revisi rule.

---

## 4. BEDAH SELURUH BARIS RULES PRAKTIKUM

### Rule A: SYN Flood (Bab V Modul - sid:1000001)
```text
alert tcp any any -> $HOME_NET 80 (msg:"POSSIBLE SYN FLOOD DETECTED"; flags:S,12; threshold:type threshold, track by_src, count 100, seconds 5; classtype:attempted-dos; sid:1000001; rev:1;)
```
* **`alert`**: Aksi IDS, catat peringatan ke log.
* **`tcp`**: Protokol layer 4 TCP.
* **`any any`**: Dari sembarang IP dan port pengirim penyerang.
* **`->`**: Arah paket masuk.
* **`$HOME_NET 80`**: Menuju server korban port 80.
* **`msg:"POSSIBLE SYN FLOOD DETECTED"`**: Pesan alert di log.
* **`flags:S,12;`**: Hanya memeriksa paket yang memiliki TCP flag SYN (`S`) aktif, dan mengabaikan bit reserved/ECN 1 dan 2 (`12`).
* **`threshold:type threshold, track by_src, count 100, seconds 5;`**: Pemicu alert jika 1 IP penyerang yang sama mengirim 100 paket SYN dalam 5 detik.
* **`classtype:attempted-dos;`**: Klasifikasi percobaan penolakan layanan (Priority 2).
* **`sid:1000001; rev:1;`**: Signature ID 1000001 versi 1.

---

### Rule B: ICMP Burst (Bab V Modul - sid:1000002)
```text
alert icmp any any -> $HOME_NET any (msg:"ICMP ECHO BURST DETECTED"; itype:8; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000002; rev:3;)
```
* **`alert`**: Aksi mencatat log.
* **`icmp`**: Protokol kendali jaringan ICMP (ping).
* **`any any -> $HOME_NET any`**: Paket ICMP dari mana saja menuju ke host server internal pada port mana saja.
* **`itype:8;`**: Membatasi pencocokan hanya pada *ICMP Type 8* (*Echo Request*), sehingga paket balasan *Echo Reply* (Type 0) tidak ikut memicu alert.
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**: Memicu alert jika penyerang mengirimkan lebih dari 8 paket ping dalam 5 detik.
* **`sid:1000002; rev:3;`**: Signature ID 1000002 versi 3.

---

### Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)
```text
alert udp any any -> $HOME_NET 53 (msg:"UDP BURST TO DNS PORT DETECTED"; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000003; rev:1;)
```
* **`alert`**: Aksi mencatat log.
* **`udp`**: Protokol transport UDP tanpa jabat tangan (*connectionless*).
* **`-> $HOME_NET 53`**: Menuju server internal pada port 53 (port baku layanan DNS).
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**: Memicu alert jika terjadi lonjakan trafik UDP ke port DNS melebihi 8 paket dalam 5 detik (indikasi serangan *DNS Amplification/Flood*).
* **`sid:1000003; rev:1;`**: Signature ID 1000003 versi 1.

---

### Rule 1: SQL Injection Tautology Bypass (sid:1000021)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi SQL Injection (Tautology Bypass)"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:2;)
```
* **`alert http any any -> $HOME_NET 80`**: Menginspeksi paket aplikasi HTTP ke port 80.
* **`flow:established,to_server;`**: Memastikan sesi TCP sudah tersambung dan paket bergerak menuju server.
* **`http.uri;`**: Fokus pencarian hanya pada URL string.
* **`content:"/vulnerabilities/sqli/"; nocase;`**: Memastikan request memang diarahkan ke halaman vuln SQLi DVWA.
* **`pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i";`**:
  * `(%27|\')`: Menangkap karakter kutip satu asli (`'`) atau bentuk encoded peramban (`%27`).
  * `(\s+|\+|%20)`: Menangkap pemisah spasi asli (`\s+`), tanda tambah peramban (`\+`), atau encoding spasi (`%20`).
  * `or`: Kata kunci logika boolean SQL.
  * `/i`: Mengabaikan perbedaan huruf kapital/kecil.
* **`classtype:web-application-attack;`**: Menandai serangan aplikasi web (Priority 1).
* **`sid:1000021; rev:2;`**: Signature ID 1000021 revisi 2.

---

### Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi Reflected XSS (Event Handler Bypass)"; flow:established,to_server; http.uri; pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui"; classtype:web-application-attack; sid:1000022; rev:2;)
```
* **`pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui";`**:
  * `<(...)`: Mendeteksi pembukaan tag HTML berbahaya yang umum dipakai untuk bypass filter (script, image, svg, iframe, video, source).
  * `[^>]+`: Memastikan karakter penutup tag `>` belum muncul sebelum atribut ditemukan.
  * `(src|onerror|onload)`: Mendeteksi event handler eksekusi otomatis JavaScript (seperti `<img src=x onerror=...>`).
  * `\s*=`: Menangkap tanda sama dengan beserta toleransi spasi.
  * `/Ui`: Modifier `U` (mencocokkan terhadap buffer normalized URI) dan `i` (case-insensitive).
* **`sid:1000022; rev:2;`**: Signature ID 1000022 revisi 2.

---

### Rule 3: CSRF Unauthorized Password Change (sid:1000023)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Upaya Eksploitasi CSRF Ganti Password"; flow:established,to_server; http.uri; content:"/vulnerabilities/csrf/"; nocase; content:"password_new="; nocase; classtype:web-application-attack; sid:1000023; rev:1;)
```
* **`content:"/vulnerabilities/csrf/"; nocase;`**: Mengunci sasaran pada endpoint modul pergantian password DVWA.
* **`content:"password_new="; nocase;`**: Mendeteksi penyematan parameter query pengubahan sandi baru pada baris URL.
* **`sid:1000023; rev:1;`**: Signature ID 1000023 revisi 1.

---

### Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)
```text
alert tcp any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Serangan DoS TCP SYN Flood ke Port Layanan DVWA"; flags:S; threshold: type both, track by_src, count 15, seconds 3; classtype:denial-of-service; sid:1000024; rev:3;)
```
* **`flags:S;`**: Hanya memfilter paket dengan bendera SYN aktif (permintaan inisiasi koneksi baru).
* **`threshold: type both, track by_src, count 15, seconds 3;`**:
  * `type both`: Mencatat alert sekali saat ambang batas tercapai dan meredam alert berulang selama jendela waktu 3 detik agar disk tidak penuh.
  * `track by_src`: Menghitung laju per satu IP penyerang.
  * `count 15, seconds 3`: Batas sensitif lab: jika ada 15 paket SYN dalam 3 detik, alert langsung terpicu.
* **`classtype:denial-of-service;`**: Klasifikasi DoS (Priority 2).
* **`sid:1000024; rev:3;`**: Signature ID 1000024 revisi 3.

---

### Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)
```text
drop http any any -> $HOME_NET 80 (msg:"[DVWA IPS BLOCK] SQL Injection Dropped"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:5;)
```
* **`drop`** (*Aksi Pencegahan IPS*): Memerintahkan kernel Linux melalui NFQUEUE untuk seketika memusnahkan (*drop/discard*) paket serangan saat itu juga. Paket tidak pernah menyentuh Apache, web DVWA menampilkan *Connection Timed Out*, dan database pengguna batal bocor.
* **Sisa parameter**: Sama persis dengan rule IDS SQLi, membuktikan bahwa perbedaan sintaks rule antara IDS dan IPS hanya terletak pada kata aksi `alert` vs `drop`.

---

## 5. KONSEPTUAL ARSITEKTUR: MODE IDS VS MODE IPS

| Parameter Evaluasi | Mode IDS (Intrusion Detection System) | Mode IPS (Intrusion Prevention System) |
|---|---|---|
| **Sifat Pertahanan** | **Pasif & Reaktif** (Mendeteksi dan mencatat) | **Aktif & Preventif** (Mencegat dan memblokir) |
| **Kata Aksi Rule** | `alert` | `drop` atau `reject` |
| **Mekanisme Jaringan** | *Out-of-band / Sniffing* via driver `AF_PACKET` | *Inline / In-path* via driver antrean kernel `NFQUEUE` |
| **Perintah Eksekusi** | `suricata --af-packet=enp0s8` atau `systemctl start suricata` | `iptables ... -j NFQUEUE` lalu `suricata -q 0` |
| **Dampak ke Penyerang** | Serangan sukses dieksekusi, database bocor | Serangan gagal total, koneksi diputus / *Timed Out* |
| **Format Pencatatan Log** | Ditandai dengan `[**]` di `fast.log` | Ditandai dengan label `[Drop]` di `fast.log` |
| **Risiko Operasional** | Nol risiko terhadap kelancaran layanan sah | Berisiko memblokir pengguna sah jika terjadi *False Positive* |

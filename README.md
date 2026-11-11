# REKAP LENGKAP PRAKTIKUM KEAMANAN JARINGAN (KAMJAR)
**Materi:** IDS/IPS Suricata, Web Application Security (DVWA), & Attack Simulation  
**Penulis:** Afif Nur Rahman (H1H024016)  
**Target Lab:** Universitas Jenderal Soedirman  

---

## DAFTAR ISI
1. [Bedah Perintah Terminal VM 1 (Kali Linux - Attacker) Kata per Kata](#1-bedah-perintah-terminal-vm-1-kali-linux---attacker)
2. [Bedah Perintah Terminal VM 2 (Ubuntu Server - Defender) Kata per Kata](#2-bedah-perintah-terminal-vm-2-ubuntu-server---defender)
3. [Bedah Total Komponen Rules Suricata (Header & Options)](#3-bedah-total-komponen-rules-suricata)
4. [Bedah Mendalam Encoding URL & Karakter Heksadesimal (%20, %27, dll)](#4-bedah-mendalam-encoding-url--karakter-heksadesimal)
5. [Bedah Mendalam Sintaks Regex PCRE (Perl-Compatible Regular Expressions)](#5-bedah-mendalam-sintaks-regex-pcre)
6. [Bedah Mendalam TCP Flags & Masking Bit ECN (flags:S,12;)](#6-bedah-mendalam-tcp-flags--masking-bit-ecn)
7. [Bedah Mendalam Sticky Buffer & Engine Preprocessor Suricata](#7-bedah-mendalam-sticky-buffer--engine-preprocessor-suricata)
8. [Bedah Mendalam Mesin Laju Trafik (Thresholding)](#8-bedah-mendalam-mesin-laju-trafik-thresholding)
9. [Bedah Seluruh Baris Rules Praktikum Kata per Kata](#9-bedah-seluruh-baris-rules-praktikum)
   - [Rule A: SYN Flood (Bab V Modul - sid:1000001)](#rule-a-syn-flood-bab-v-modul---sid1000001)
   - [Rule B: ICMP Burst (Bab V Modul - sid:1000002)](#rule-b-icmp-burst-bab-v-modul---sid1000002)
   - [Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)](#rule-c-udp-burst-port-53-dns-bab-v-modul---sid1000003)
   - [Rule 1: SQL Injection Tautology Bypass (sid:1000021)](#rule-1-sql-injection-tautology-bypass---sid1000021)
   - [Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)](#rule-2-reflected-xss-event-handler-bypass---sid1000022)
   - [Rule 3: CSRF Unauthorized Password Change (sid:1000023)](#rule-3-csrf-unauthorized-password-change---sid1000023)
   - [Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)](#rule-4-dos-tcp-syn-flood-port-80-dvwa---sid1000024)
   - [Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)](#rule-5-mode-ips---sql-injection-dropped---sid1000021-rev5)
10. [Konseptual Arsitektur: Mode IDS vs Mode IPS](#10-konseptual-arsitektur-mode-ids-vs-mode-ips)

---

## 1. BEDAH PERINTAH TERMINAL VM 1 (KALI LINUX - ATTACKER)

### A. Perintah DoS TCP SYN Flood Terukur
```bash
sudo hping3 -S -p 80 -c 50 --faster 192.168.2.3
```
* **`sudo`** (*SuperUser DO*): Menjalankan perintah dengan hak akses root/administrator tertinggi. Wajib digunakan karena pembuatan paket mentah (*raw socket creation*) dan manipulasi flag TCP secara manual dilarang untuk user Linux biasa tanpa izin kernel.
* **`hping3`**: Program generator dan penganalisis paket jaringan berbasis CLI yang mampu menyusun paket IP, TCP, UDP, dan ICMP kustom.
* **`-S`** (*SYN Flag*): Mengaktifkan secara spesifik bendera TCP **SYN** (*Synchronize*), yaitu paket inisiasi koneksi pada *TCP Three-Way Handshake*.
* **`-p 80`** (*Port destination*): Mengarahkan paket serangan tepat ke port 80 (port layanan web HTTP Apache / DVWA).
* **`-c 50`** (*Count 50*): Membatasi jumlah paket yang dikirimkan tepat sebanyak 50 paket, lalu proses berhenti otomatis. Ini mencegah server hang total dan menjaga lab tetap terkendali.
* **`--faster`** (*Fast rate*): Mengatur kecepatan pengiriman paket dengan interval 10 milidetik (10.000 mikrodetik), atau setara dengan **100 paket per detik**. Laju ini menjamin ambang batas Suricata terlampaui seketika.
* **`192.168.2.3`**: Alamat IP mesin target/korban (VM Ubuntu Server).

### B. Perintah DoS Mode Flood Ekstrem
```bash
sudo hping3 -S -p 80 --flood 192.168.2.3
```
* **`--flood`**: Mengirimkan paket secepat mungkin (*as fast as possible*) sesuai kapasitas maksimal bandwidth kartu jaringan tanpa memproses atau mendengarkan paket balasan (*no reply processing*).
  * *Konsekuensi teknis:* I/O buffer terminal Kali Linux terisi penuh hingga ratusan ribu event/detik, menyebabkan tombol jeda `Ctrl + Z` tersendat di antrean CPU.

### C. Perintah Menghentikan Paksa Proses Macet
```bash
sudo killall -9 hping3
```
* **`killall`**: Utilitas untuk mengirimkan sinyal penghentian ke seluruh proses berdasarkan nama aplikasinya.
* **`-9`** (*SIGKILL*): Sinyal pemusnahan mutlak pada kernel Linux. Sinyal ini tidak bisa diabaikan, ditunda, atau ditahan oleh aplikasi yang sedang hang/macet.
* **`hping3`**: Nama target proses yang dimatikan.

### D. Perintah Pengujian ICMP Ping
```bash
ping -c 3 192.168.2.3
```
* **`ping`**: Utilitas penguji konektivitas jaringan berbasis protokol ICMP.
* **`-c 3`** (*Count 3*): Mengirimkan tepat 3 paket *ICMP Echo Request*.
* **`192.168.2.3`**: Alamat IP target.

### E. Perintah Eksploitasi Web via CLI
```bash
curl -i -s "http://192.168.2.3/dvwa/vulnerabilities/sqli/?id=%27+OR+%271%27%3D%271&Submit=Submit"
```
* **`curl`** (*Client URL*): Alat CLI untuk mentransfer data melalui protokol HTTP/HTTPS.
* **`-i`** (*Include Headers*): Menampilkan response header HTTP dari server (`HTTP/1.1 200 OK`, `Set-Cookie`, `Server: Apache`) bersamaan dengan body HTML.
* **`-s`** (*Silent*): Menyembunyikan progress meter agar tampilan terminal bersih.
* **`"..."`**: URL endpoint yang disisipi payload. Tanda petik dua wajib dipasang agar karakter `&`, `?`, `=`, `'` tidak dieksekusi sebagai operator shell Linux.

---

## 2. BEDAH PERINTAH TERMINAL VM 2 (UBUNTU SERVER - DEFENDER)

### A. Validasi Sintaks Konfigurasi Suricata
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
* **`sudo`**: Hak akses root.
* **`suricata`**: Biner aplikasi mesin Intrusion Detection System (IDS).
* **`-T`** (*Test configuration*): Menjalankan Suricata dalam mode uji coba sintaks. Suricata akan mengompilasi konfigurasi dan seluruh rules ke memori, memastikan tidak ada galat (error kurung/spasi/variabel), lalu langsung keluar tanpa sniffing antarmuka.
* **`-c`** (*Config file path*): Menentukan jalur berkas konfigurasi master.
* **`/etc/suricata/suricata.yaml`**: Jalur file konfigurasi master Suricata.
* **`-v`** (*Verbose*): Menampilkan log inisialisasi detail langkah demi langkah ke layar terminal.

### B. Live Reload Rules Tanpa Restart Layanan
```bash
sudo suricatasc -c reload-rules
```
* **`suricatasc`** (*Suricata Socket Client*): Utilitas CLI untuk berinteraksi langsung dengan daemon Suricata yang berjalan melalui UNIX domain socket (`suricata-command.socket`).
* **`-c`** (*Command*): Memberikan instruksi spesifik ke socket Suricata.
* **`reload-rules`**: Perintah agar Suricata membaca ulang file `.rules` dan menukarnya secara atomik di memori (*zero packet loss / zero downtime*).

### C. Live Monitoring Log Alert
```bash
sudo tail -f /var/log/suricata/fast.log
```
* **`tail`**: Program pembaca baris paling akhir dari sebuah berkas teks.
* **`-f`** (*Follow mode*): Mengunci terminal dalam status mendengarkan (*listen*). Setiap kali Suricata menulis baris peringatan serangan baru, terminal langsung menampilkannya secara real-time.
* **`/var/log/suricata/fast.log`**: Berkas teks tempat Suricata mencatat alert ringkas satu baris (*single-line alert*).

### D. Manajemen Service Systemd
```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```
* **`systemctl`** (*Systemd Control*): Utilitas pengendali sistem inisialisasi dan manajer layanan (*systemd*).
* **`restart`**: Menghentikan proses secara total (*SIGTERM*) dan menyalakannya kembali dari nol.
* **`status`**: Memeriksa status kesehatan layanan (apakah aktif hijau, PID proses, dan histori log).

### E. Inspeksi Antarmuka Jaringan
```bash
ip -br a
```
* **`ip`**: Utilitas modern jaringan Linux (paket `iproute2`, pengganti `ifconfig`).
* **`-br`** (*Brief*): Menampilkan data dalam format tabel satu baris ringkas per kartu jaringan.
* **`a`** (*Address*): Menampilkan informasi alamat IPv4/IPv6 yang terpasang pada antarmuka.

### F. Mode IPS Menggunakan Iptables & NFQUEUE
```bash
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -v
```
* **`iptables`**: Program firewall paket filter di kernel Linux.
* **`-I INPUT`** (*Insert into INPUT chain*): Menyisipkan aturan di urutan paling awal pada rantai *INPUT* (lalu lintas masuk menuju server lokal).
* **`-p tcp`** (*Protocol TCP*): Aturan hanya berlaku untuk protokol TCP.
* **`--dport 80`** (*Destination Port 80*): Mengunci paket yang tujuannya ke port web 80.
* **`-j NFQUEUE`** (*Jump to Netfilter Queue*): Aksi target. Paket ditahan di kernel dan dialihkan ke antrean memori *NFQUEUE*.
* **`--queue-num 0`**: Nomor antrean memori yang digunakan (antrean nomor 0).
* **`-q 0`** (*Queue 0 pada Suricata*): Memerintahkan Suricata untuk bertindak sebagai worker IPS yang menginspeksi antrean nomor 0. Paket normal diberi vonis `NF_ACCEPT`, paket jahat diberi vonis `NF_DROP`.

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
   * Menandakan arah lalu lintas data. `->` berarti satu arah (dari kiri/pengirim menuju kanan/penerima). `<>` berarti dua arah bolak-balik.
5. **Destination IP (`$HOME_NET`):**
   * Variabel yang didefinisikan pada `suricata.yaml` untuk mewakili jaringan atau server target yang dilindungi (contoh: `192.168.2.3/32`).
6. **Destination Port (`80`, `53`, `any`):**
   * Port tujuan layanan target. `80` untuk HTTP web server, `53` untuk DNS server, `any` untuk sembarang port.

---

## 4. BEDAH MENDALAM ENCODING URL & KARAKTER HEKSADESIMAL

Dalam protokol web HTTP (RFC 3986), karakter tertentu di dalam URI tidak boleh dikirim dalam bentuk karakter mentah karena bertabrakan dengan karakter kendali protokol (seperti spasi, tanda tanya `?`, garis miring `/`, atau tanda petik `'`). Karakter-karakter tersebut harus diubah menjadi **Percent-Encoding (URL Encoding)**.

Format URL Encoding adalah tanda persen (`%`) yang diikuti oleh **dua digit heksadesimal (basis 16)** yang merepresentasikan nilai byte karakter tersebut pada **Tabel ASCII (American Standard Code for Information Interchange)**.

### A. Mengapa `%20` adalah Spasi?
* Karakter **Spasi (*Space*)** memiliki nilai desimal ASCII **`32`**.
* Konversi nilai desimal `32` ke sistem heksadesimal (basis 16):
  $$32 = (2 \times 16^1) + (0 \times 16^0) = \mathbf{20_{16}}$$
* Oleh karena itu, representasi URL Encoding untuk spasi ditulis sebagai **`%20`**.

### B. Mengapa `%27` adalah Tanda Petik Tunggal (`'`)?
* Karakter **Kutip Tunggal (*Single Quote / Apostrophe*)** memiliki nilai desimal ASCII **`39`**.
* Konversi nilai desimal `39` ke sistem heksadesimal (basis 16):
  $$39 = (2 \times 16^1) + (7 \times 16^0) = \mathbf{27_{16}}$$
* Oleh karena itu, representasi URL Encoding untuk tanda petik tunggal ditulis sebagai **`%27`**.

### C. Mengapa Ada Tanda Plus (`+`) untuk Spasi?
* Berdasarkan standar formulir web HTML (*MIME Type: `application/x-www-form-urlencoded`*), ketika pengguna mengetik spasi pada formulir pencarian (seperti input User ID di DVWA) dan mengirimkannya via metode GET, peramban secara otomatis mengonversi spasi menjadi tanda plus (**`+`**) sebelum dikirim ke server.
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
   * `\+`: Mencocokkan tanda tambah literal (`+`). Karakter plus harus di-escape (`\+`) karena jika berdiri sendiri tanpa backslash, simbol `+` dianggap sebagai quantifier.
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

### B. Mengapa Sintaksnya Tertulis `flags:S,12;`?
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

### Rule A: SYN Flood (Bab V Modul - sid:1000001)
```text
alert tcp any any -> $HOME_NET 80 (msg:"POSSIBLE SYN FLOOD DETECTED"; flags:S,12; threshold:type threshold, track by_src, count 100, seconds 5; classtype:attempted-dos; sid:1000001; rev:1;)
```
* **`alert`**: Aksi Mode IDS, catat kejadian ke berkas log.
* **`tcp`**: Protokol transport TCP.
* **`any any`**: Dari alamat IP dan port sumber mana pun.
* **`->`**: Arah paket masuk satu arah.
* **`$HOME_NET 80`**: Menuju IP server target yang dilindungi pada port layanan 80.
* **`msg:"POSSIBLE SYN FLOOD DETECTED"`**: Teks pesan peringatan yang dicetak ke file log.
* **`flags:S,12;`**: Memeriksa flag SYN aktif dengan masking bit ECN 1 & 2.
* **`threshold:type threshold, track by_src, count 100, seconds 5;`**: Memicu alert jika penyerang mengirimkan 100 paket SYN dalam 5 detik.
* **`classtype:attempted-dos;`**: Kategori percobaan penolakan layanan (Priority 2).
* **`sid:1000001; rev:1;`**: Signature ID 1000001 revisi 1.

---

### Rule B: ICMP Burst (Bab V Modul - sid:1000002)
```text
alert icmp any any -> $HOME_NET any (msg:"ICMP ECHO BURST DETECTED"; itype:8; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000002; rev:3;)
```
* **`alert`**: Aksi mencatat log.
* **`icmp`**: Protokol kendali jaringan ICMP.
* **`any any -> $HOME_NET any`**: Paket ICMP dari mana saja menuju ke server target pada port mana saja.
* **`itype:8;`**: Membatasi pencocokan hanya pada *ICMP Type 8 (Echo Request)*. Mencegah paket balasan server memicu false alarm.
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**: Memicu alert jika penyerang mengirim lebih dari 8 paket ping dalam 5 detik.
* **`classtype:attempted-dos;`**: Klasifikasi Priority 2.
* **`sid:1000002; rev:3;`**: Signature ID 1000002 revisi 3.

---

### Rule C: UDP Burst Port 53 DNS (Bab V Modul - sid:1000003)
```text
alert udp any any -> $HOME_NET 53 (msg:"UDP BURST TO DNS PORT DETECTED"; threshold:type threshold, track by_src, count 8, seconds 5; classtype:attempted-dos; sid:1000003; rev:1;)
```
* **`alert`**: Aksi mencatat log.
* **`udp`**: Protokol transport UDP tanpa jabat tangan (*connectionless*).
* **`-> $HOME_NET 53`**: Menuju port layanan DNS 53.
* **`threshold:type threshold, track by_src, count 8, seconds 5;`**: Memicu alert jika terjadi lonjakan trafik UDP melebihi 8 paket dalam 5 detik (deteksi anomali *DNS Flood/Amplification*).
* **`sid:1000003; rev:1;`**: Signature ID 1000003 revisi 1.

---

### Rule 1: SQL Injection Tautology Bypass (sid:1000021)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi SQL Injection (Tautology Bypass)"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:2;)
```
* **`alert http any any -> $HOME_NET 80`**: Menginspeksi request protokol HTTP yang menyasar port 80 server target.
* **`flow:established,to_server;`**: Memastikan sesi TCP telah terjalin dan arah paket bergerak dari klien menuju server.
* **`http.uri;`**: Mengunci ruang lingkup pencarian hanya pada URI buffer.
* **`content:"/vulnerabilities/sqli/";`**: String wajib yang memastikan target adalah modul rentan SQLi DVWA.
* **`nocase;`**: Mengabaikan kapitalisasi huruf pada parameter `content`.
* **`pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i";`**: Regex deteksi injeksi kutip tunggal (`'` atau `%27`) yang diikuti pemisah spasi/tanda tambah, kata kunci `or`, dan spasi berikutnya.
* **`classtype:web-application-attack;`**: Kategori serangan aplikasi web (otomatis memetakan ke **Priority 1 / High**).
* **`sid:1000021; rev:2;`**: Signature ID 1000021 revisi 2.

---

### Rule 2: Reflected XSS Event Handler Bypass (sid:1000022)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Eksploitasi Reflected XSS (Event Handler Bypass)"; flow:established,to_server; http.uri; pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui"; classtype:web-application-attack; sid:1000022; rev:2;)
```
* **`pcre:"/<(script|img|svg|iframe|video|source)[^>]+(src|onerror|onload)\s*=/Ui";`**: Regex deteksi pembukaan tag HTML berbahaya (`<`) yang memuat atribut eksekusi skrip otomatis (`onerror=`, `onload=`) sebelum kurung siku tutup tag (`>`) muncul.
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000022; rev:2;`**: Signature ID 1000022 revisi 2.

---

### Rule 3: CSRF Unauthorized Password Change (sid:1000023)
```text
alert http any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Upaya Eksploitasi CSRF Ganti Password"; flow:established,to_server; http.uri; content:"/vulnerabilities/csrf/"; nocase; content:"password_new="; nocase; classtype:web-application-attack; sid:1000023; rev:1;)
```
* **`content:"/vulnerabilities/csrf/"; nocase;`**: Mengunci endpoint spesifik modul pengubahan kredensial DVWA.
* **`content:"password_new="; nocase;`**: Memeriksa keberadaan passing parameter sensitif pergantian kata sandi pada URI request.
* **`classtype:web-application-attack;`**: Kategori serangan web (Priority 1).
* **`sid:1000023; rev:1;`**: Signature ID 1000023 revisi 1.

---

### Rule 4: DoS TCP SYN Flood Port 80 DVWA (sid:1000024)
```text
alert tcp any any -> $HOME_NET 80 (msg:"[DVWA ATTACK] Terdeteksi Serangan DoS TCP SYN Flood ke Port Layanan DVWA"; flags:S; threshold: type both, track by_src, count 15, seconds 3; classtype:denial-of-service; sid:1000024; rev:3;)
```
* **`flags:S;`**: Memeriksa paket di mana bendera SYN aktif murni.
* **`threshold: type both, track by_src, count 15, seconds 3;`**: Memicu alert satu kali ketika 15 paket SYN diterima dari IP yang sama dalam kurun waktu 3 detik, lalu menahan alert lanjutan selama interval tersebut agar storage log tidak jebol.
* **`classtype:denial-of-service;`**: Klasifikasi DoS (otomatis memetakan ke **Priority 2 / Medium**).
* **`sid:1000024; rev:3;`**: Signature ID 1000024 revisi 3.

---

### Rule 5: Mode IPS - SQL Injection Dropped (sid:1000021 rev:5)
```text
drop http any any -> $HOME_NET 80 (msg:"[DVWA IPS BLOCK] SQL Injection Dropped"; flow:established,to_server; http.uri; content:"/vulnerabilities/sqli/"; nocase; pcre:"/(%27|\')(\s+|\+|%20)or(\s+|\+|%20)/i"; classtype:web-application-attack; sid:1000021; rev:5;)
```
* **`drop`**: Aksi pencegahan intrusi aktif. Paket serangan langsung dimusnahkan oleh kernel Linux via antrean NFQUEUE. Paket tidak pernah mencapai port 80 web server Apache, peramban menampilkan galat *Connection Timed Out*, dan basis data pengguna batal bocor.
* **Sisa parameter**: Identik dengan rule nomor 1, membuktikan bahwa perbedaan sintaks rule antara IDS dan IPS murni hanya pada kata aksi pertama (`alert` vs `drop`).

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

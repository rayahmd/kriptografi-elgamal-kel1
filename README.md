# Tugas Kriptografi: Diffie-Hellman & ElGamal

Program Python yang menunjukkan **fungsi setiap tahapan** protokol Diffie-Hellman dan kriptosistem ElGamal dalam **satu studi kasus**, tanpa library atau framework jadi. Semua perhitungan kriptografi ditulis sendiri.

Kelompok 1 Kriptografi
- Raya Ahmad Syarif 5027241041
- M Fatihul Qolbi Ash Shidqi 5027241023
- Zein Muhammad Hasan 5027241035
---

## Daftar Isi

1. [Kesesuaian dengan Ketentuan Tugas](#kesesuaian-dengan-ketentuan-tugas)
2. [Studi Kasus](#studi-kasus)
3. [Struktur Proyek](#struktur-proyek)
4. [Cara Menjalankan](#cara-menjalankan)
5. [Alur Tahapan Program](#alur-tahapan-program)
6. [Dasar Teori](#dasar-teori)
7. [Penjelasan Fungsi](#penjelasan-fungsi)
8. [Contoh Output](#contoh-output)
9. [Verifikasi dengan Contoh Buku](#verifikasi-dengan-contoh-buku)
10. [Pengujian](#pengujian)
11. [Analisis Keamanan](#analisis-keamanan)
12. [Referensi](#referensi)

---

## Kesesuaian dengan Ketentuan Tugas

| Ketentuan | Pemenuhan |
|---|---|
| **Tanpa library / framework jadi** | Tidak memakai library kriptografi atau matematika (`cryptography`, `pycryptodome`, `sympy`, `hashlib`, `math`, dsb). Bahkan fungsi bawaan `pow()` tidak dipakai. Perpangkatan modular, invers modular, uji prima, dan pencarian generator diimplementasikan manual di `matematika.py`. |
| **Menunjukkan fungsi setiap tahapan** | Program menampilkan 12 tahap berurutan. Setiap tahap menunjukkan rumus, nilai input, nilai output, dan untuk bilangan kecil juga langkah perhitungannya (tabel *square-and-multiply* dan langkah Extended Euclid). |
| **Dalam 1 studi kasus** | Diffie-Hellman dan ElGamal dijalankan dalam satu skenario yang sama (Alice, Bob, dan penyadap Eve) dengan parameter publik `(p, g)` yang sama. |

**Modul bawaan Python yang dipakai:**

| Modul | Kegunaan | Keterangan |
|---|---|---|
| `secrets` | Sumber bilangan acak dari sistem operasi | Hanya menghasilkan angka acak, tidak melakukan perhitungan kriptografi apa pun |
| `sys` | Membaca argumen command line dan keluar program | Bukan bagian dari algoritma |
| `unittest` | Hanya di `test_program.py` | File pengujian, bukan bagian dari program utama |

---

## Studi Kasus

> **Pengiriman Token Presensi Rahasia**
>
> Alice (ketua kelas) ingin mengirim token presensi kepada Bob lewat grup chat kelas. Grup itu terbuka, sehingga **Eve** (penyadap) dapat membaca semua pesan yang lewat.
>
> - **Bagian A (Diffie-Hellman):** Alice dan Bob menyepakati kunci rahasia bersama tanpa pernah mengirim kunci itu.
> - **Bagian B (ElGamal):** Alice mengenkripsi token presensi `"Token presensi: KRIPTO-27"` dengan kunci publik Bob, lalu Bob mendekripsinya.
>
> Program juga menampilkan apa yang dilihat Eve, mensimulasikan serangan brute force dari Eve, dan menunjukkan bahwa ElGamal sebenarnya adalah Diffie-Hellman sekali pakai.

Parameter default: `p = 2357`, `g = 2` (diambil dari *Handbook of Applied Cryptography*, Contoh 8.17). Bilangan ini cukup kecil agar setiap langkah perhitungan dapat dicek dengan tangan.

---

## Struktur Proyek

```
tugas-dh-elgamal/
├── matematika.py       # Teori bilangan buatan sendiri: square-and-multiply, Extended Euclid,
│                       # invers modular, Miller-Rabin, safe prime, generator
├── diffie_hellman.py   # Fungsi untuk setiap tahap Diffie-Hellman
├── elgamal.py          # Fungsi untuk setiap tahap ElGamal
├── main.py             # Program studi kasus (menjalankan dan menampilkan semua tahap)
├── test_program.py     # 18 unit test (opsional)
└── README.md
```

---

## Cara Menjalankan

Kebutuhan: **Python 3.8 atau lebih baru**. Tidak perlu `pip install` apa pun.

```bash
# Studi kasus default (p = 2357, g = 2), langkah perhitungan ditampilkan lengkap
python main.py

# Ganti pesan yang dienkripsi
python main.py --pesan "Kuis hari Jumat dibatalkan"

# Pakai safe prime 512-bit acak (lebih realistis; jejak perhitungan disembunyikan)
python main.py --bits 512

# Mode interaktif: masukkan p, g, kunci privat, dan pesan sendiri
python main.py --interaktif

# Bantuan
python main.py --help
```

Contoh sesi mode interaktif:

```
Mode interaktif. Tekan Enter untuk memakai nilai default/acak.
  Bilangan prima p (> 256) [Enter = 2357]: 467
  Generator g (0 = cari otomatis) [Enter = 0]:
  Kunci privat Alice a [Enter = acak]: 100
  Kunci privat Bob b [Enter = acak]: 200
  Kunci privat ElGamal Bob x [Enter = acak]: 300
  Pesan [Enter = 'Token presensi: KRIPTO-27']: Halo Bob
```

Program akan menolak input yang tidak valid: `p` bukan prima, `p ≤ 256`, `g` bukan generator, atau kunci privat di luar rentang `[2, p − 2]`.

> **Catatan:** jejak perhitungan langkah demi langkah hanya ditampilkan jika `p` ≤ 32 bit, karena untuk bilangan ratusan bit tabelnya akan ratusan baris.

---

## Alur Tahapan Program

| Tahap | Pelaku | Proses | Rumus | Fungsi |
|---|---|---|---|---|
| **1** | Alice & Bob | Menyepakati parameter publik, uji prima `p`, cek generator `g` | `g^((p−1)/f) ≠ 1 mod p` untuk tiap faktor prima `f` dari `p − 1` | `apakah_prima`, `faktor_prima`, `apakah_generator` |
| | | **BAGIAN A: DIFFIE-HELLMAN** | | |
| **2** | Alice & Bob | Memilih kunci privat | `a, b ∈ [2, p−2]` acak | `dh.pilih_kunci_privat` |
| **3** | Alice & Bob | Menghitung kunci publik | `A = g^a mod p`, `B = g^b mod p` | `dh.hitung_kunci_publik` |
| **4** | Alice ↔ Bob | Bertukar kunci publik lewat saluran terbuka | Eve melihat `p, g, A, B` | – |
| **5** | Alice & Bob | Validasi kunci publik lawan, menghitung kunci bersama | `K = B^a mod p = A^b mod p` | `dh.validasi_kunci_publik`, `dh.hitung_kunci_bersama` |
| **6** | Eve | Serangan brute force logaritma diskrit | cari `e` dengan `g^e ≡ A` | `dh.serangan_brute_force` |
| | | **BAGIAN B: ELGAMAL** | | |
| **7** | Bob | Membangkitkan pasangan kunci | `x` acak, `y = g^x mod p` | `eg.bangkitkan_kunci` |
| **8** | Alice | Mengubah pesan menjadi blok angka | teks → byte UTF-8 → blok `m` (`1 ≤ m < p`) | `eg.teks_ke_blok` |
| **9** | Alice | Mengenkripsi setiap blok | `k` acak, `c1 = g^k mod p`, `c2 = m · y^k mod p` | `eg.enkripsi_blok` |
| **10** | Alice → Bob | Mengirim ciphertext | Eve melihat semua `(c1, c2)` | – |
| **11** | Bob | Mendekripsi setiap blok | `s = c1^x mod p`, `m = c2 · s⁻¹ mod p` | `eg.dekripsi_blok` |
| **12** | Bob | Mengubah blok kembali menjadi teks, membandingkan dengan pesan asli | blok `m` → byte → teks | `eg.blok_ke_teks` |

Di akhir, program menampilkan **ringkasan** nilai apa saja yang diketahui oleh Alice, Bob, dan Eve.

---

## Dasar Teori

### Masalah Logaritma Diskrit

Diberikan bilangan prima `p`, generator `g`, dan `y = g^x mod p`, mencari `x` disebut **Discrete Logarithm Problem (DLP)**. Menghitung `g^x mod p` sangat cepat dengan *square-and-multiply*, tetapi kebalikannya sangat sulit untuk `p` yang besar. Diffie-Hellman dan ElGamal sama-sama bergantung pada kesulitan ini.

### Generator

`g` disebut generator (akar primitif) modulo `p` jika `g^1, g^2, …, g^(p−1)` menghasilkan semua bilangan `1, 2, …, p−1`. Cara mengeceknya: untuk setiap faktor prima `f` dari `p − 1`, harus berlaku `g^((p−1)/f) mod p ≠ 1`.

Contoh `p = 2357`: `p − 1 = 2356 = 2² × 19 × 31`, dan untuk `g = 2`:
- `2^1178 mod 2357 = 2356 ≠ 1`
- `2^124 mod 2357 = 1882 ≠ 1`
- `2^76 mod 2357 = 1564 ≠ 1`

maka 2 adalah generator.

### Diffie-Hellman

| Langkah | Alice | Saluran publik | Bob |
|---|---|---|---|
| 1 | Pilih rahasia `a` | | Pilih rahasia `b` |
| 2 | `A = g^a mod p` | `A →` dan `← B` | `B = g^b mod p` |
| 3 | `K = B^a mod p` | | `K = A^b mod p` |

**Mengapa hasilnya sama:**

```
B^a = (g^b)^a = g^(ab) = (g^a)^b = A^b   (mod p)
```

### ElGamal

**Pembangkitan kunci (Bob):** pilih `x` acak, hitung `y = g^x mod p`. Kunci publik `(p, g, y)`, kunci privat `x`.

**Enkripsi (Alice), untuk setiap blok `m`:**
```
k  = acak, berbeda untuk setiap blok
c1 = g^k mod p
c2 = m · y^k mod p
```

**Dekripsi (Bob):**
```
s  = c1^x mod p
m  = c2 · s⁻¹ mod p
```

**Mengapa dekripsi benar:**
```
c1^x = (g^k)^x = (g^x)^k = y^k
c2 · (y^k)⁻¹ = m · y^k · (y^k)⁻¹ = m   (mod p)
```

**Hubungan dengan Diffie-Hellman:** `k` berperan sebagai kunci privat sementara Alice dan `c1 = g^k` sebagai kunci publik sementaranya. Nilai `s = y^k = c1^x = g^(xk)` adalah "kunci bersama Diffie-Hellman" antara Alice dan Bob, yang dipakai untuk menutupi pesan. Program menunjukkan hal ini di akhir Tahap 12.

### Square-and-Multiply

Untuk menghitung `g^e mod p`, eksponen `e` ditulis dalam biner lalu dibaca dari kiri. Untuk setiap bit, hasil dikuadratkan, dan jika bitnya 1 hasil juga dikalikan dengan `g`. Semuanya dilakukan modulo `p`. Dengan cara ini, eksponen 2048 bit hanya membutuhkan sekitar 4096 perkalian, bukan 2^2048 perkalian.

### Extended Euclid

Untuk mencari `s⁻¹ mod p`, dicari `t` dengan `s · t ≡ 1 (mod p)`. Algoritma Extended Euclid mencari `x, y` sehingga `s·x + p·y = fpb(s, p) = 1`, maka `s⁻¹ = x mod p`.

---

## Penjelasan Fungsi

### `matematika.py`

| Fungsi | Keterangan |
|---|---|
| `acak_rentang(bawah, atas)` | Bilangan acak di `[bawah, atas]` |
| `fpb(a, b)` | Faktor persekutuan terbesar (algoritma Euclid) |
| `extended_euclid(a, b, jejak)` | Mengembalikan `(d, x, y)` dengan `a·x + b·y = d`. Langkah-langkahnya bisa dicatat ke `jejak` |
| `invers_modulo(a, m, jejak)` | `a⁻¹ mod m` via Extended Euclid |
| `pangkat_modulo(basis, eksponen, modulus, jejak)` | `basis^eksponen mod modulus` via square-and-multiply, langkahnya bisa dicatat |
| `apakah_prima(n)` | Uji primalitas Miller-Rabin 40 putaran (peluang salah ≤ 4⁻⁴⁰) |
| `faktor_prima(n)` | Faktor prima berbeda dari `n` (pembagian percobaan) |
| `bangkitkan_safe_prime(bit)` | Safe prime `p = 2q + 1`, dipakai pada mode `--bits` |
| `apakah_generator(g, p, faktor)` / `cari_generator(p, faktor)` | Cek dan cari generator |

### `diffie_hellman.py`

| Fungsi | Tahap |
|---|---|
| `pilih_kunci_privat(p, g)` | 2 |
| `hitung_kunci_publik(g, privat, p)` | 3 |
| `validasi_kunci_publik(publik, p)` | 5 (menolak 0, 1, p−1, dan nilai di luar rentang) |
| `hitung_kunci_bersama(publik_lawan, privat, p)` | 5 |
| `serangan_brute_force(g, publik, p)` | 6 (simulasi Eve) |

### `elgamal.py`

| Fungsi | Tahap |
|---|---|
| `bangkitkan_kunci(p, g, x)` | 7 |
| `ukuran_blok(p)`, `teks_ke_blok(teks, p)` | 8 |
| `enkripsi_blok(m, kunci_publik, k)` | 9 |
| `dekripsi_blok(c1, c2, kunci_privat)` | 11 |
| `blok_ke_teks(daftar_m, panjang, p)` | 12 |
| `enkripsi_teks` / `dekripsi_teks` | Gabungan tahap 8–9 dan 11–12 untuk dipakai sebagai library |

**Pemecahan blok:** setiap blok berisi `⌊(bit(p) − 1) / 8⌋` byte, sehingga nilainya selalu kurang dari `p`. Untuk `p = 2357` (12 bit), satu blok = 1 karakter. Setiap blok ditambah 1 supaya tidak pernah bernilai 0, karena `m = 0` menghasilkan `c2 = 0` dan pesan langsung bocor.

---

## Contoh Output

Potongan output `python main.py` (angka acak berbeda setiap kali dijalankan):

```
[Tahap 1] Alice dan Bob menyepakati parameter publik (p, g)
------------------------------------------------------------------------
  p = 2357
  Uji Miller-Rabin terhadap p : PRIMA
  Faktor prima dari p - 1 = 2356 : 2, 19, 31
  g = 2
  Syarat generator: g^((p-1)/f) mod p != 1 untuk setiap faktor prima f
    g^((p-1)/2) mod p = 2356       != 1  OK
    g^((p-1)/19) mod p = 1882       != 1  OK
    g^((p-1)/31) mod p = 1564       != 1  OK
  => g adalah generator. Parameter (p, g) diumumkan di grup (Eve ikut tahu).

[Tahap 3] Alice dan Bob menghitung kunci publik
------------------------------------------------------------------------
  Alice: A = g^a mod p = 2^672 mod 2357 = 2145
    Perhitungan 2^672 mod 2357 dengan square-and-multiply
    672 dalam biner = 1010100000
      bit | operasi          | hasil sementara
    ------+------------------+-----------------
        1 | kuadrat x basis  | 2
        0 | kuadrat          | 4
        1 | kuadrat x basis  | 32
        0 | kuadrat          | 1024
        1 | kuadrat x basis  | 1779
        0 | kuadrat          | 1747
        0 | kuadrat          | 2051
        0 | kuadrat          | 1713
        0 | kuadrat          | 2261
        0 | kuadrat          | 2145
  Bob  : B = g^b mod p = 2^1561 mod 2357 = 2252

[Tahap 5] Alice dan Bob menghitung kunci bersama
------------------------------------------------------------------------
  Alice: K = B^a mod p = 2252^672 mod 2357 = 586
  Bob  : K = A^b mod p = 2145^1561 mod 2357 = 586
  Kunci bersama sama? YA

[Tahap 6] Eve mencoba memecahkan kunci (serangan brute force logaritma diskrit)
------------------------------------------------------------------------
  Ditemukan e = 672 setelah 673 percobaan (e = a)
  Eve menghitung K = B^e mod p = 586  -> BERHASIL
  Kesimpulan: dengan p sekecil ini (12 bit), DH mudah dipecahkan.

[Tahap 9] Alice mengenkripsi setiap blok dengan kunci publik Bob
------------------------------------------------------------------------
   No | char |      m |      k |    y^k |     c1 |     c2
  ----+------+--------+--------+--------+--------+-------
    1 |    T |     85 |   2161 |   1335 |   1144 |    339
    2 |    o |    112 |    351 |   1153 |    867 |   1858
  ...
   21 |    T |     85 |   2131 |   1559 |   2295 |    523

  Catatan: blok 1 dan 21 sama-sama m = 85, tetapi ciphertext-nya
  berbeda: 1144,339 vs 2295,523 karena k berbeda.

[Tahap 11] Bob mendekripsi setiap blok dengan kunci privat x
------------------------------------------------------------------------
  Contoh blok 1: s = 1144^251 mod 2357 = 1335
    Mencari 1335^-1 mod 2357 dengan Extended Euclid:
      1335 = 0 x 2357 + 1335
      2357 = 1 x 1335 + 1022
      ...
      2 = 2 x 1 + 0
    Diperoleh 1335^-1 mod 2357 = 1363   (cek: 1335 x 1363 mod 2357 = 1)
                 m = 339 x 1363 mod 2357 = 85

[Tahap 12] Bob mengubah blok angka kembali menjadi teks
------------------------------------------------------------------------
  Hasil dekripsi : 'Token presensi: KRIPTO-27'
  Pesan asli     : 'Token presensi: KRIPTO-27'
  Sama?            YA

  Hubungan dengan Diffie-Hellman (blok 1):
    Alice menghitung y^k  mod p = 1335
    Bob   menghitung c1^x mod p = 1335
    Keduanya sama (= g^(xk)). Jadi ElGamal adalah Diffie-Hellman sekali pakai.

========================================================================
 RINGKASAN
========================================================================
  Nilai                       |  Alice |   Bob  |   Eve
  ----------------------------+--------+--------+--------
  Parameter p, g              |  tahu  |  tahu  |  tahu
  Kunci privat DH a           |  tahu  |    -   |    -
  Kunci privat DH b           |    -   |  tahu  |    -
  Kunci publik DH A, B        |  tahu  |  tahu  |  tahu
  Kunci bersama DH K          |  tahu  |  tahu  |    -
  Kunci publik ElGamal y      |  tahu  |  tahu  |  tahu
  Kunci privat ElGamal x      |    -   |  tahu  |    -
  Bilangan acak k             |  tahu  |    -   |    -
  Ciphertext (c1, c2)         |  tahu  |  tahu  |  tahu
  Pesan asli                  |  tahu  |  tahu  |    -

  Status akhir: SEMUA TAHAP BERHASIL
```

---

## Verifikasi dengan Contoh Buku

Kebenaran implementasi dicocokkan dengan contoh yang sudah dipublikasikan (diuji otomatis di `test_program.py`):

**Handbook of Applied Cryptography, Contoh 8.17 (ElGamal)**

| | Nilai buku | Hasil program |
|---|---|---|
| `p, g` | 2357, 2 | 2357, 2 |
| Kunci privat `x` | 1751 | 1751 |
| Kunci publik `y = 2^1751 mod 2357` | 1185 | 1185 |
| Pesan `m`, acak `k` | 2035, 1520 | 2035, 1520 |
| `c1 = 2^1520 mod 2357` | 1430 | 1430 |
| `c2 = 2035 · 1185^1520 mod 2357` | 697 | 697 |
| Dekripsi | 2035 | 2035 |

**Contoh Diffie-Hellman klasik (`p = 23`, `g = 5`, `a = 6`, `b = 15`)**

| | Nilai |
|---|---|
| `A = 5^6 mod 23` | 8 |
| `B = 5^15 mod 23` | 19 |
| `K = 19^6 mod 23 = 8^15 mod 23` | 2 |

---

## Pengujian

```bash
python -m unittest -v test_program
```

18 unit test, semuanya lulus:

| Kelompok | Yang diuji |
|---|---|
| `TestMatematika` | `pangkat_modulo` dibandingkan dengan perkalian berulang, jejak square-and-multiply, Extended Euclid, invers modular, Miller-Rabin (termasuk menolak bilangan Carmichael 561, 1105, 1729, …), faktorisasi & generator, safe prime |
| `TestDiffieHellman` | Contoh `p = 23`, kunci bersama selalu sama (safe prime 256-bit), penolakan kunci publik lemah, brute force pada `p` kecil |
| `TestElGamal` | Contoh Handbook 8.17, contoh `p = 23`, sifat probabilistik, teks (ASCII, Unicode, emoji, byte nol, kosong) pada `p` kecil maupun 256-bit, kunci salah gagal, hubungan dengan DH, validasi rentang |

---

## Analisis Keamanan

1. **Ukuran `p`.** Studi kasus default memakai `p = 2357` (12 bit) **hanya untuk edukasi**, agar perhitungan bisa dicek dengan tangan. Tahap 6 membuktikan bahwa Eve memecahkannya dalam kurang dari 2357 percobaan. Untuk keamanan nyata, `p` minimal **2048 bit** (coba `--bits 512` untuk melihat brute force gagal).

2. **Man-in-the-Middle.** Diffie-Hellman murni tidak mengautentikasi pihak yang berkomunikasi. Eve yang aktif dapat menyamar sebagai Bob kepada Alice dan sebaliknya. Solusinya adalah menandatangani kunci publik (sertifikat digital, seperti pada TLS).

3. **`k` tidak boleh dipakai ulang.** Jika `k` sama dipakai untuk dua pesan, maka `c2 / c2' ≡ m / m' (mod p)`, dan mengetahui satu pesan membuka pesan lainnya. Program ini membangkitkan `k` baru untuk setiap blok.

4. **Enkripsi per karakter pada `p` kecil.** Dengan `p = 2357`, satu blok = satu karakter. Meski ciphertext untuk huruf yang sama selalu berbeda (lihat catatan di Tahap 10), ukuran ciphertext jauh lebih besar dari pesan. Dalam praktik ElGamal hanya mengenkripsi kunci sesi, lalu pesan dienkripsi dengan cipher simetris (*hybrid encryption*).

5. **Malleability.** Penyerang dapat mengubah `c2` menjadi `2·c2` sehingga hasil dekripsinya `2·m`, tanpa mengetahui `m`. Integritas pesan perlu dijaga dengan mekanisme terpisah (MAC atau tanda tangan digital).

6. **Validasi kunci publik.** Program menolak kunci publik `1` dan `p − 1` yang memaksa kunci bersama menjadi nilai yang mudah ditebak (*small subgroup attack*).

7. **Bukan untuk produksi.** Implementasi ini dibuat untuk pembelajaran dan tidak tahan terhadap serangan waktu (*timing attack*). Untuk sistem nyata gunakan pustaka yang sudah teruji.

---

## Referensi

1. W. Diffie dan M. E. Hellman, "New Directions in Cryptography," *IEEE Transactions on Information Theory*, vol. 22, no. 6, 1976.
2. T. ElGamal, "A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms," *IEEE Transactions on Information Theory*, vol. 31, no. 4, 1985.
3. A. Menezes, P. van Oorschot, S. Vanstone, *Handbook of Applied Cryptography*, CRC Press, 1996. Bab 2 (Extended Euclid, square-and-multiply), Bab 4 (Miller-Rabin), Bab 8 (ElGamal, Contoh 8.17), Bab 12 (Diffie-Hellman).
4. W. Stallings, *Cryptography and Network Security: Principles and Practice*, Pearson.

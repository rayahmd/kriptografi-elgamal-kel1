"""
matematika.py
Fungsi-fungsi teori bilangan yang ditulis sendiri (tanpa library matematika
atau kriptografi). Dipakai oleh diffie_hellman.py dan elgamal.py.

Satu-satunya modul bawaan yang dipakai adalah `secrets`, HANYA sebagai sumber
bilangan acak dari sistem operasi. Semua perhitungan (perpangkatan modular,
invers, uji prima, generator) diimplementasikan manual di file ini.
"""

import secrets


# ---------------------------------------------------------------------------
# Bilangan acak
# ---------------------------------------------------------------------------

def acak_rentang(bawah, atas):
    """Bilangan bulat acak di rentang [bawah, atas] (inklusif)."""
    if bawah > atas:
        raise ValueError("Rentang acak tidak valid")
    return bawah + secrets.randbelow(atas - bawah + 1)


def acak_bit(jumlah_bit):
    """Bilangan acak ganjil yang panjangnya tepat `jumlah_bit` bit."""
    n = secrets.randbits(jumlah_bit)
    n |= 1 << (jumlah_bit - 1)  # bit tertinggi = 1 agar panjangnya pas
    n |= 1                      # ganjil
    return n


# ---------------------------------------------------------------------------
# FPB, Extended Euclid, invers modular
# ---------------------------------------------------------------------------

def fpb(a, b):
    """Faktor persekutuan terbesar dengan algoritma Euclid."""
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_euclid(a, b, jejak=None):
    """Extended Euclid: mengembalikan (d, x, y) sehingga a*x + b*y = d = fpb(a, b).

    Jika `jejak` berupa list, setiap langkah pembagian (a, b, hasil_bagi, sisa)
    dicatat agar bisa ditampilkan.
    """
    x_lama, x = 1, 0
    y_lama, y = 0, 1
    while b != 0:
        q = a // b
        sisa = a - q * b
        if jejak is not None:
            jejak.append((a, b, q, sisa))
        a, b = b, sisa
        x_lama, x = x, x_lama - q * x
        y_lama, y = y, y_lama - q * y
    return a, x_lama, y_lama


def invers_modulo(a, m, jejak=None):
    """Invers a^-1 mod m, yaitu bilangan t dengan (a * t) mod m = 1."""
    d, x, _ = extended_euclid(a % m, m, jejak)
    if d != 1:
        raise ValueError(f"{a} tidak memiliki invers modulo {m} (fpb = {d})")
    return x % m


# ---------------------------------------------------------------------------
# Perpangkatan modular (square-and-multiply)
# ---------------------------------------------------------------------------

def pangkat_modulo(basis, eksponen, modulus, jejak=None):
    """Menghitung (basis ^ eksponen) mod modulus dengan square-and-multiply.

    Eksponen dibaca bit per bit dari kiri (MSB). Untuk setiap bit:
      - hasil dikuadratkan
      - jika bit = 1, hasil dikalikan basis
    Semua dilakukan modulo `modulus` agar angka tidak membengkak.

    Jika `jejak` berupa list, setiap langkah (bit, operasi, hasil) dicatat.
    """
    if modulus == 1:
        return 0
    if eksponen < 0:
        raise ValueError("Eksponen harus non-negatif")
    basis %= modulus
    hasil = 1
    for bit in bin(eksponen)[2:]:
        hasil = (hasil * hasil) % modulus
        operasi = "kuadrat"
        if bit == "1":
            hasil = (hasil * basis) % modulus
            operasi = "kuadrat x basis"
        if jejak is not None:
            jejak.append((bit, operasi, hasil))
    return hasil


# ---------------------------------------------------------------------------
# Bilangan prima
# ---------------------------------------------------------------------------

def _saringan_eratosthenes(batas):
    tandai = [True] * (batas + 1)
    tandai[0] = tandai[1] = False
    i = 2
    while i * i <= batas:
        if tandai[i]:
            for j in range(i * i, batas + 1, i):
                tandai[j] = False
        i += 1
    return [i for i in range(batas + 1) if tandai[i]]


PRIMA_KECIL = _saringan_eratosthenes(1000)


def apakah_prima(n, putaran=40):
    """Uji primalitas Miller-Rabin (memakai pangkat_modulo buatan sendiri).

    Peluang bilangan komposit lolos uji <= 4^(-putaran).
    """
    if n < 2:
        return False
    for p in PRIMA_KECIL:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Tulis n - 1 = 2^s * d dengan d ganjil
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(putaran):
        a = acak_rentang(2, n - 2)
        x = pangkat_modulo(a, d, n)
        if x == 1 or x == n - 1:
            continue
        lolos = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                lolos = True
                break
        if not lolos:
            return False  # a adalah saksi bahwa n komposit
    return True


def faktor_prima(n):
    """Faktor prima berbeda dari n dengan pembagian percobaan.

    Hanya praktis untuk n yang kecil-sedang (misalnya p - 1 untuk p < 10^12).
    """
    faktor = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            faktor.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        faktor.append(n)
    return faktor


def bangkitkan_safe_prime(jumlah_bit):
    """Membangkitkan safe prime p = 2q + 1 (p dan q sama-sama prima).

    Mengembalikan (p, q).
    """
    if jumlah_bit < 16:
        raise ValueError("Panjang bit minimal 16")
    while True:
        q = acak_bit(jumlah_bit - 1)
        p = 2 * q + 1
        # Saringan cepat sebelum Miller-Rabin
        gagal = False
        for kecil in PRIMA_KECIL[:200]:
            if (q % kecil == 0 and q != kecil) or (p % kecil == 0 and p != kecil):
                gagal = True
                break
        if gagal:
            continue
        if apakah_prima(q) and apakah_prima(p):
            return p, q


# ---------------------------------------------------------------------------
# Generator (akar primitif)
# ---------------------------------------------------------------------------

def apakah_generator(g, p, faktor_p_kurang_1):
    """g adalah generator modulo p jika g^((p-1)/f) != 1 untuk setiap faktor
    prima f dari p - 1."""
    if not 2 <= g <= p - 1:
        return False
    for f in faktor_p_kurang_1:
        if pangkat_modulo(g, (p - 1) // f, p) == 1:
            return False
    return True


def cari_generator(p, faktor_p_kurang_1):
    """Mencari generator terkecil modulo p."""
    for g in range(2, p):
        if apakah_generator(g, p, faktor_p_kurang_1):
            return g
    raise ValueError("Generator tidak ditemukan (apakah p prima?)")

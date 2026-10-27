"""
diffie_hellman.py
Tahapan protokol pertukaran kunci Diffie-Hellman, masing-masing satu fungsi.

  Tahap 1  Sepakati parameter publik p (prima) dan g (generator)
  Tahap 2  Masing-masing pihak memilih kunci privat     a, b
  Tahap 3  Masing-masing menghitung kunci publik        A = g^a mod p, B = g^b mod p
  Tahap 4  Kunci publik dipertukarkan lewat saluran terbuka
  Tahap 5  Masing-masing menghitung kunci bersama       K = B^a mod p = A^b mod p
"""

from matematika import acak_rentang, pangkat_modulo


def pilih_kunci_privat(p, g):
    """Tahap 2: memilih kunci privat acak di [2, p-2].

    Nilai yang menghasilkan kunci publik 1 atau p-1 dilewati karena lemah.
    """
    while True:
        privat = acak_rentang(2, p - 2)
        publik = pangkat_modulo(g, privat, p)
        if publik not in (1, p - 1):
            return privat


def hitung_kunci_publik(g, privat, p, jejak=None):
    """Tahap 3: kunci publik = g^privat mod p."""
    if not 2 <= privat <= p - 2:
        raise ValueError("Kunci privat harus berada di rentang [2, p-2]")
    return pangkat_modulo(g, privat, p, jejak)


def validasi_kunci_publik(publik, p):
    """Menolak kunci publik lemah (0, 1, p-1, atau di luar rentang).

    Kunci publik 1 atau p-1 memaksa kunci bersama menjadi 1 atau +-1 sehingga
    mudah ditebak (small subgroup attack).
    """
    if not 2 <= publik <= p - 2:
        raise ValueError(f"Kunci publik {publik} tidak valid (harus di [2, p-2])")


def hitung_kunci_bersama(publik_lawan, privat, p, jejak=None):
    """Tahap 5: kunci bersama = (kunci publik lawan)^privat mod p."""
    validasi_kunci_publik(publik_lawan, p)
    return pangkat_modulo(publik_lawan, privat, p, jejak)


def serangan_brute_force(g, publik, p, batas=10_000_000):
    """Simulasi penyerang: mencari eksponen e dengan g^e mod p = publik
    (logaritma diskrit) dengan mencoba satu per satu.

    Mengembalikan (e, jumlah_percobaan), atau (None, jumlah_percobaan) jika
    melewati batas.
    """
    nilai = 1
    for e in range(0, min(p - 1, batas)):
        if nilai == publik:
            return e, e + 1
        nilai = (nilai * g) % p
    return None, min(p - 1, batas)

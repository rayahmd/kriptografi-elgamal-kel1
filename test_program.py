"""
test_program.py
Pengujian otomatis (opsional, bukan bagian dari program utama).
Jalankan: python -m unittest -v test_program
"""

import unittest

import diffie_hellman as dh
import elgamal as eg
from matematika import (
    apakah_generator,
    apakah_prima,
    bangkitkan_safe_prime,
    cari_generator,
    extended_euclid,
    faktor_prima,
    fpb,
    invers_modulo,
    pangkat_modulo,
)


class TestMatematika(unittest.TestCase):
    def test_pangkat_modulo_cocok_dengan_rumus(self):
        for basis, eks, mod in [(2, 10, 1000), (5, 6, 23), (7, 0, 13), (123456, 789, 1000003), (3, 200, 2**61 - 1)]:
            hasil_manual = 1
            for _ in range(eks):
                hasil_manual = (hasil_manual * basis) % mod
            self.assertEqual(pangkat_modulo(basis, eks, mod), hasil_manual)

    def test_jejak_square_and_multiply(self):
        jejak = []
        self.assertEqual(pangkat_modulo(5, 6, 23, jejak), 8)
        self.assertEqual([j[0] for j in jejak], list("110"))
        self.assertEqual(jejak[-1][2], 8)

    def test_fpb_dan_extended_euclid(self):
        self.assertEqual(fpb(240, 46), 2)
        d, x, y = extended_euclid(240, 46)
        self.assertEqual(d, 2)
        self.assertEqual(240 * x + 46 * y, 2)

    def test_invers_modulo(self):
        self.assertEqual(invers_modulo(6, 23), 4)
        for a in range(1, 100):
            self.assertEqual((a * invers_modulo(a, 101)) % 101, 1)
        with self.assertRaises(ValueError):
            invers_modulo(6, 12)

    def test_apakah_prima(self):
        prima = [n for n in range(60) if apakah_prima(n)]
        self.assertEqual(prima, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59])
        for carmichael in [561, 1105, 1729, 2465, 2821, 6601, 8911, 1024651]:
            self.assertFalse(apakah_prima(carmichael))
        self.assertTrue(apakah_prima(2**127 - 1))
        self.assertFalse(apakah_prima(2**128 + 1))

    def test_faktor_dan_generator(self):
        self.assertEqual(faktor_prima(2356), [2, 19, 31])
        self.assertTrue(apakah_generator(2, 2357, [2, 19, 31]))
        self.assertTrue(apakah_generator(5, 23, faktor_prima(22)))
        self.assertFalse(apakah_generator(2, 23, faktor_prima(22)))  # orde 2 mod 23 = 11
        self.assertEqual(cari_generator(23, faktor_prima(22)), 5)

    def test_safe_prime(self):
        p, q = bangkitkan_safe_prime(128)
        self.assertEqual(p, 2 * q + 1)
        self.assertEqual(p.bit_length(), 128)
        self.assertTrue(apakah_prima(p) and apakah_prima(q))
        self.assertTrue(apakah_generator(cari_generator(p, [2, q]), p, [2, q]))


class TestDiffieHellman(unittest.TestCase):
    def test_contoh_buku_p23(self):
        A = dh.hitung_kunci_publik(5, 6, 23)
        B = dh.hitung_kunci_publik(5, 15, 23)
        self.assertEqual((A, B), (8, 19))
        self.assertEqual(dh.hitung_kunci_bersama(B, 6, 23), 2)
        self.assertEqual(dh.hitung_kunci_bersama(A, 15, 23), 2)

    def test_kunci_bersama_selalu_sama(self):
        p, q = bangkitkan_safe_prime(256)
        g = cari_generator(p, [2, q])
        for _ in range(5):
            a, b = dh.pilih_kunci_privat(p, g), dh.pilih_kunci_privat(p, g)
            A, B = dh.hitung_kunci_publik(g, a, p), dh.hitung_kunci_publik(g, b, p)
            self.assertEqual(dh.hitung_kunci_bersama(B, a, p), dh.hitung_kunci_bersama(A, b, p))

    def test_tolak_kunci_publik_lemah(self):
        for buruk in [0, 1, 2356, 2357, -1]:
            with self.assertRaises(ValueError):
                dh.hitung_kunci_bersama(buruk, 100, 2357)

    def test_brute_force_p_kecil(self):
        A = dh.hitung_kunci_publik(2, 1234, 2357)
        e, _ = dh.serangan_brute_force(2, A, 2357)
        self.assertEqual(e, 1234)


class TestElGamal(unittest.TestCase):
    def test_contoh_handbook_8_17(self):
        # Menezes et al., Handbook of Applied Cryptography, Contoh 8.17
        pub, priv = eg.bangkitkan_kunci(2357, 2, x=1751)
        self.assertEqual(pub["y"], 1185)
        h = eg.enkripsi_blok(2035, pub, k=1520)
        self.assertEqual((h["c1"], h["c2"]), (1430, 697))
        self.assertEqual(eg.dekripsi_blok(1430, 697, priv)["m"], 2035)

    def test_contoh_p23(self):
        pub, priv = eg.bangkitkan_kunci(23, 5, x=6)
        h = eg.enkripsi_blok(10, pub, k=3)
        self.assertEqual((h["c1"], h["c2"]), (10, 14))
        self.assertEqual(eg.dekripsi_blok(10, 14, priv)["m"], 10)

    def test_enkripsi_probabilistik(self):
        pub, _ = eg.bangkitkan_kunci(2357, 2)
        hasil = {(eg.enkripsi_blok(42, pub)["c1"]) for _ in range(20)}
        self.assertGreater(len(hasil), 1)

    def test_teks_p_kecil_dan_besar(self):
        p_besar, q = bangkitkan_safe_prime(256)
        g_besar = cari_generator(p_besar, [2, q])
        pesan_uji = ["A", "Token presensi: KRIPTO-27", "Unicode: é ñ 漢字 🔐", "\x00\x00awal nol", "x" * 100, ""]
        for p, g in [(2357, 2), (257, 3), (p_besar, g_besar)]:
            pub, priv = eg.bangkitkan_kunci(p, g)
            for pesan in pesan_uji:
                self.assertEqual(eg.dekripsi_teks(eg.enkripsi_teks(pesan, pub), priv), pesan)

    def test_kunci_salah_gagal(self):
        pub, _ = eg.bangkitkan_kunci(2357, 2, x=1000)
        _, priv_lain = eg.bangkitkan_kunci(2357, 2, x=1001)
        h = eg.enkripsi_blok(500, pub)
        self.assertNotEqual(eg.dekripsi_blok(h["c1"], h["c2"], priv_lain)["m"], 500)

    def test_hubungan_dengan_dh(self):
        pub, priv = eg.bangkitkan_kunci(2357, 2)
        h = eg.enkripsi_blok(99, pub)
        self.assertEqual(h["s"], eg.dekripsi_blok(h["c1"], h["c2"], priv)["s"])

    def test_validasi_rentang(self):
        pub, _ = eg.bangkitkan_kunci(2357, 2)
        for m in [0, 2357, -5]:
            with self.assertRaises(ValueError):
                eg.enkripsi_blok(m, pub)
        with self.assertRaises(ValueError):
            eg.ukuran_blok(251)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""
main.py
STUDI KASUS: Pengiriman Token Presensi Rahasia

  Alice (ketua kelas) ingin mengirim token presensi kepada Bob melalui grup
  chat kelas. Grup itu terbuka, sehingga Eve (penyadap) dapat membaca semua
  pesan yang lewat. Alice dan Bob:
    - Bagian A: menyepakati kunci rahasia bersama dengan Diffie-Hellman
    - Bagian B: mengirim token presensi terenkripsi dengan ElGamal
  Program menampilkan hasil setiap tahap, termasuk langkah perhitungannya.

Cara menjalankan:
  python main.py                          # studi kasus default (p = 2357, g = 2)
  python main.py --pesan "Teks lain"      # ganti pesan
  python main.py --bits 512               # pakai safe prime 512-bit acak
  python main.py --interaktif             # masukkan p, g, kunci, dan pesan sendiri
"""

import sys

import diffie_hellman as dh
import elgamal as eg
from matematika import (
    apakah_generator,
    apakah_prima,
    bangkitkan_safe_prime,
    cari_generator,
    faktor_prima,
    pangkat_modulo,
)

PESAN_DEFAULT = "Token presensi: KRIPTO-27"
P_DEFAULT = 2357   # contoh dari Handbook of Applied Cryptography (Menezes), Contoh 8.17
G_DEFAULT = 2
LEBAR = 72
BATAS_JEJAK_BIT = 32        # jejak perhitungan hanya ditampilkan jika p <= 32 bit
BATAS_BRUTE_FORCE = 10_000_000

BANTUAN = __doc__


# ---------------------------------------------------------------------------
# Tampilan
# ---------------------------------------------------------------------------

def judul(teks):
    print()
    print("=" * LEBAR)
    print(" " + teks)
    print("=" * LEBAR)


def tahap(nomor, teks):
    print()
    print(f"[Tahap {nomor}] {teks}")
    print("-" * LEBAR)


def angka(n):
    """Menampilkan bilangan; yang terlalu panjang diringkas."""
    s = str(n)
    if len(s) <= 40:
        return s
    return f"{s[:16]}...{s[-16:]} ({n.bit_length()} bit)"


def tampil_jejak_pangkat(basis, eksponen, modulus, jejak):
    print(f"    Perhitungan {basis}^{eksponen} mod {modulus} dengan square-and-multiply")
    print(f"    {eksponen} dalam biner = {bin(eksponen)[2:]}")
    print(f"    {'bit':>5} | {'operasi':<16} | hasil sementara")
    print(f"    {'-' * 5}-+-{'-' * 16}-+-{'-' * 16}")
    for bit, operasi, hasil in jejak:
        print(f"    {bit:>5} | {operasi:<16} | {hasil}")


def tampil_jejak_euclid(a, m, jejak, hasil):
    print(f"    Mencari {a}^-1 mod {m} dengan Extended Euclid:")
    for x, y, q, r in jejak:
        print(f"      {x} = {q} x {y} + {r}")
    print(f"    Diperoleh {a}^-1 mod {m} = {hasil}   (cek: {a} x {hasil} mod {m} = {(a * hasil) % m})")


def kecil(p):
    return p.bit_length() <= BATAS_JEJAK_BIT


# ---------------------------------------------------------------------------
# Tahap 1: parameter publik (dipakai bersama oleh DH dan ElGamal)
# ---------------------------------------------------------------------------

def siapkan_parameter(p, g, faktor=None):
    tahap(1, "Alice dan Bob menyepakati parameter publik (p, g)")
    print(f"  p = {angka(p)}")
    prima = apakah_prima(p)
    print(f"  Uji Miller-Rabin terhadap p : {'PRIMA' if prima else 'BUKAN PRIMA'}")
    if not prima:
        sys.exit("  p harus bilangan prima. Program dihentikan.")

    if faktor is None:
        faktor = faktor_prima(p - 1)
    print(f"  Faktor prima dari p - 1 = {angka(p - 1)} : {', '.join(angka(f) for f in faktor)}")

    if g is None:
        g = cari_generator(p, faktor)
        print(f"  g tidak ditentukan, dicari generator terkecil: g = {g}")
    else:
        print(f"  g = {angka(g)}")

    print("  Syarat generator: g^((p-1)/f) mod p != 1 untuk setiap faktor prima f")
    for f in faktor:
        nilai = pangkat_modulo(g, (p - 1) // f, p)
        status = "!= 1  OK" if nilai != 1 else "= 1   GAGAL"
        print(f"    g^((p-1)/{angka(f)}) mod p = {angka(nilai):<10} {status}")
    if not apakah_generator(g, p, faktor):
        sys.exit("  g bukan generator modulo p. Program dihentikan.")

    print("  => g adalah generator. Parameter (p, g) diumumkan di grup (Eve ikut tahu).")
    return p, g


# ---------------------------------------------------------------------------
# Bagian A: Diffie-Hellman
# ---------------------------------------------------------------------------

def bagian_diffie_hellman(p, g, a=None, b=None):
    judul("BAGIAN A - DIFFIE-HELLMAN: menyepakati kunci rahasia bersama")

    tahap(2, "Alice dan Bob memilih kunci privat masing-masing")
    if a is None:
        a = dh.pilih_kunci_privat(p, g)
    if b is None:
        b = dh.pilih_kunci_privat(p, g)
    print(f"  Alice memilih a = {angka(a)}   (rahasia, tidak pernah dikirim)")
    print(f"  Bob   memilih b = {angka(b)}   (rahasia, tidak pernah dikirim)")

    tahap(3, "Alice dan Bob menghitung kunci publik")
    jejak = [] if kecil(p) else None
    A = dh.hitung_kunci_publik(g, a, p, jejak)
    B = dh.hitung_kunci_publik(g, b, p)
    print(f"  Alice: A = g^a mod p = {g}^{angka(a)} mod {angka(p)} = {angka(A)}")
    if jejak:
        tampil_jejak_pangkat(g, a, p, jejak)
    print(f"  Bob  : B = g^b mod p = {g}^{angka(b)} mod {angka(p)} = {angka(B)}")

    tahap(4, "Pertukaran kunci publik melalui grup chat (saluran terbuka)")
    print(f"  Alice --> Bob   : A = {angka(A)}")
    print(f"  Bob   --> Alice : B = {angka(B)}")
    print(f"  Yang diketahui Eve : p = {angka(p)}, g = {g}, A = {angka(A)}, B = {angka(B)}")
    print(f"  Yang TIDAK diketahui Eve : a dan b")

    tahap(5, "Alice dan Bob menghitung kunci bersama")
    jejak = [] if kecil(p) else None
    dh.validasi_kunci_publik(B, p)
    dh.validasi_kunci_publik(A, p)
    print("  Validasi: A dan B berada di rentang [2, p-2]  OK")
    K_alice = dh.hitung_kunci_bersama(B, a, p, jejak)
    K_bob = dh.hitung_kunci_bersama(A, b, p)
    print(f"  Alice: K = B^a mod p = {angka(B)}^{angka(a)} mod {angka(p)} = {angka(K_alice)}")
    if jejak:
        tampil_jejak_pangkat(B, a, p, jejak)
    print(f"  Bob  : K = A^b mod p = {angka(A)}^{angka(b)} mod {angka(p)} = {angka(K_bob)}")
    print(f"  Kunci bersama sama? {'YA' if K_alice == K_bob else 'TIDAK'}")
    print("  Alasan: B^a = (g^b)^a = g^(ab) = (g^a)^b = A^b (mod p)")

    tahap(6, "Eve mencoba memecahkan kunci (serangan brute force logaritma diskrit)")
    if p <= BATAS_BRUTE_FORCE:
        print(f"  Eve mencari e sehingga {g}^e mod {p} = {A} dengan mencoba satu per satu ...")
        e, percobaan = dh.serangan_brute_force(g, A, p)
        K_eve = pangkat_modulo(B, e, p)
        print(f"  Ditemukan e = {e} setelah {percobaan} percobaan (e {'=' if e == a else '!='} a)")
        print(f"  Eve menghitung K = B^e mod p = {K_eve}  -> {'BERHASIL' if K_eve == K_alice else 'GAGAL'}")
        print(f"  Kesimpulan: dengan p sekecil ini ({p.bit_length()} bit), DH mudah dipecahkan.")
        print("  Dalam praktik p minimal 2048 bit, sehingga percobaan sebanyak ~2^2048")
        print("  tidak mungkin diselesaikan. Coba jalankan: python main.py --bits 512")
    else:
        print(f"  p berukuran {p.bit_length()} bit -> ruang pencarian kira-kira 2^{p.bit_length()} kemungkinan.")
        print(f"  Eve mencoba {BATAS_BRUTE_FORCE:,} kemungkinan pertama ...")
        e, percobaan = dh.serangan_brute_force(g, A, p, BATAS_BRUTE_FORCE)
        print(f"  Hasil: {'ditemukan' if e is not None else 'TIDAK ditemukan'} setelah {percobaan:,} percobaan.")
        print("  Kesimpulan: kunci aman dari brute force karena p sangat besar.")

    return K_alice


# ---------------------------------------------------------------------------
# Bagian B: ElGamal
# ---------------------------------------------------------------------------

def bagian_elgamal(p, g, pesan, x=None):
    judul("BAGIAN B - ELGAMAL: mengirim token presensi terenkripsi")

    tahap(7, "Bob membangkitkan pasangan kunci ElGamal")
    jejak = [] if kecil(p) else None
    kunci_publik, kunci_privat = eg.bangkitkan_kunci(p, g, x, jejak)
    x, y = kunci_privat["x"], kunci_publik["y"]
    print(f"  Kunci privat Bob : x = {angka(x)}   (rahasia)")
    print(f"  Kunci publik Bob : y = g^x mod p = {g}^{angka(x)} mod {angka(p)} = {angka(y)}")
    if jejak:
        tampil_jejak_pangkat(g, x, p, jejak)
    print(f"  Bob mengumumkan kunci publik (p, g, y) = ({angka(p)}, {g}, {angka(y)})")

    tahap(8, "Alice mengubah pesan menjadi blok angka")
    daftar_m, panjang = eg.teks_ke_blok(pesan, p)
    ukuran = eg.ukuran_blok(p)
    data = pesan.encode("utf-8")
    print(f"  Pesan        : {pesan!r}")
    print(f"  Byte UTF-8   : {list(data)}")
    print(f"  Panjang      : {panjang} byte")
    print(f"  Ukuran blok  : {ukuran} byte per blok (agar setiap blok < p)")
    print(f"  Jumlah blok  : {len(daftar_m)}")
    print("  Setiap blok diberi +1 agar tidak pernah bernilai 0.")
    if kecil(p):
        print(f"  Blok m       : {daftar_m}")

    tahap(9, "Alice mengenkripsi setiap blok dengan kunci publik Bob")
    print("  Rumus: k acak (baru untuk tiap blok), c1 = g^k mod p, c2 = m * y^k mod p")
    hasil_enkripsi = [eg.enkripsi_blok(m, kunci_publik) for m in daftar_m]
    if kecil(p):
        print(f"  {'No':>3} | {'char':>4} | {'m':>6} | {'k':>6} | {'y^k':>6} | {'c1':>6} | {'c2':>6}")
        print(f"  {'-' * 3}-+-{'-' * 4}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}")
        for i, h in enumerate(hasil_enkripsi):
            karakter = chr(h["m"] - 1) if ukuran == 1 and 32 <= h["m"] - 1 < 127 else "."
            print(f"  {i + 1:>3} | {karakter:>4} | {h['m']:>6} | {h['k']:>6} | {h['s']:>6} | {h['c1']:>6} | {h['c2']:>6}")
        h = hasil_enkripsi[0]
        print(f"  Contoh blok 1: c1 = {g}^{h['k']} mod {p} = {h['c1']}")
        print(f"                 c2 = {h['m']} x {y}^{h['k']} mod {p} = {h['m']} x {h['s']} mod {p} = {h['c2']}")
    else:
        for i, h in enumerate(hasil_enkripsi):
            print(f"  Blok {i + 1}: m  = {angka(h['m'])}")
            print(f"           k  = {angka(h['k'])}")
            print(f"           c1 = {angka(h['c1'])}")
            print(f"           c2 = {angka(h['c2'])}")

    tahap(10, "Alice mengirim ciphertext ke grup chat")
    ciphertext = [(h["c1"], h["c2"]) for h in hasil_enkripsi]
    if kecil(p):
        print(f"  Ciphertext (c1, c2): {ciphertext}")
    else:
        print(f"  {len(ciphertext)} pasang (c1, c2) dikirim.")
    print("  Eve melihat semua pasangan (c1, c2) tetapi tidak tahu x, sehingga tidak")
    print("  bisa menghitung y^k untuk membuka pesan.")
    # Tunjukkan sifat probabilistik: blok yang sama -> ciphertext berbeda
    for i in range(len(daftar_m)):
        for j in range(i + 1, len(daftar_m)):
            if daftar_m[i] == daftar_m[j]:
                print(f"  Catatan: blok {i + 1} dan {j + 1} sama-sama m = {daftar_m[i]}, tetapi ciphertext-nya")
                print(f"  berbeda: {angka(ciphertext[i][0])},{angka(ciphertext[i][1])} vs "
                      f"{angka(ciphertext[j][0])},{angka(ciphertext[j][1])} karena k berbeda.")
                break
        else:
            continue
        break

    tahap(11, "Bob mendekripsi setiap blok dengan kunci privat x")
    print("  Rumus: s = c1^x mod p, s^-1 dicari dengan Extended Euclid, m = c2 * s^-1 mod p")
    hasil_dekripsi = []
    for i, (c1, c2) in enumerate(ciphertext):
        jejak_euclid = [] if (i == 0 and kecil(p)) else None
        hasil_dekripsi.append(eg.dekripsi_blok(c1, c2, kunci_privat, jejak_euclid))
        if jejak_euclid:
            h = hasil_dekripsi[0]
            print(f"  Contoh blok 1: s = {c1}^{x} mod {p} = {h['s']}")
            tampil_jejak_euclid(h["s"], p, jejak_euclid, h["s_invers"])
            print(f"                 m = {c2} x {h['s_invers']} mod {p} = {h['m']}")
    if kecil(p):
        print(f"  {'No':>3} | {'c1':>6} | {'c2':>6} | {'s':>6} | {'s^-1':>6} | {'m':>6}")
        print(f"  {'-' * 3}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}-+-{'-' * 6}")
        for i, ((c1, c2), h) in enumerate(zip(ciphertext, hasil_dekripsi)):
            print(f"  {i + 1:>3} | {c1:>6} | {c2:>6} | {h['s']:>6} | {h['s_invers']:>6} | {h['m']:>6}")
    else:
        for i, h in enumerate(hasil_dekripsi):
            print(f"  Blok {i + 1}: s = {angka(h['s'])}, m = {angka(h['m'])}")

    tahap(12, "Bob mengubah blok angka kembali menjadi teks")
    daftar_m_bob = [h["m"] for h in hasil_dekripsi]
    pesan_bob = eg.blok_ke_teks(daftar_m_bob, panjang, p)
    print(f"  Hasil dekripsi : {pesan_bob!r}")
    print(f"  Pesan asli     : {pesan!r}")
    print(f"  Sama?            {'YA' if pesan_bob == pesan else 'TIDAK'}")

    # Hubungan ElGamal dengan Diffie-Hellman
    h_enk, h_dek = hasil_enkripsi[0], hasil_dekripsi[0]
    print()
    print("  Hubungan dengan Diffie-Hellman (blok 1):")
    print(f"    Alice menghitung y^k  mod p = {angka(h_enk['s'])}")
    print(f"    Bob   menghitung c1^x mod p = {angka(h_dek['s'])}")
    print("    Keduanya sama (= g^(xk)). Jadi ElGamal adalah Diffie-Hellman sekali pakai:")
    print("    k berperan seperti kunci privat sementara Alice, c1 = g^k kunci publiknya.")
    return pesan_bob == pesan


# ---------------------------------------------------------------------------
# Input & program utama
# ---------------------------------------------------------------------------

def baca_opsi(argv):
    opsi = {"pesan": PESAN_DEFAULT, "bits": None, "interaktif": False}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(BANTUAN)
            sys.exit(0)
        elif arg == "--interaktif":
            opsi["interaktif"] = True
        elif arg == "--pesan" and i + 1 < len(argv):
            opsi["pesan"] = argv[i + 1]
            i += 1
        elif arg == "--bits" and i + 1 < len(argv):
            opsi["bits"] = int(argv[i + 1])
            i += 1
        else:
            print(f"Opsi tidak dikenal: {arg}")
            print(BANTUAN)
            sys.exit(1)
        i += 1
    return opsi


def tanya_angka(label, default=None):
    keterangan = f"[Enter = {default}]" if default is not None else "[Enter = acak]"
    while True:
        teks = input(f"  {label} {keterangan}: ").strip()
        if not teks:
            return default
        try:
            return int(teks)
        except ValueError:
            print("  Masukkan bilangan bulat.")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    opsi = baca_opsi(sys.argv[1:])
    pesan = opsi["pesan"]
    a = b = x = None
    faktor = None

    if opsi["interaktif"]:
        print("Mode interaktif. Tekan Enter untuk memakai nilai default/acak.")
        try:
            p = tanya_angka("Bilangan prima p (> 256)", P_DEFAULT)
            if p <= 256:
                sys.exit("  p harus > 256 agar 1 karakter (1 byte) muat dalam satu blok.")
            g = tanya_angka("Generator g (0 = cari otomatis)", 0) or None
            a = tanya_angka("Kunci privat Alice a")
            b = tanya_angka("Kunci privat Bob b")
            x = tanya_angka("Kunci privat ElGamal Bob x")
            for nama, nilai in (("a", a), ("b", b), ("x", x)):
                if nilai is not None and not 2 <= nilai <= p - 2:
                    sys.exit(f"  Kunci privat {nama} harus berada di rentang [2, {p - 2}].")
            masukan = input(f"  Pesan [Enter = {pesan!r}]: ")
            pesan = masukan or pesan
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n  Input dibatalkan.")
    elif opsi["bits"]:
        print(f"Membangkitkan safe prime {opsi['bits']}-bit ...")
        p, q = bangkitkan_safe_prime(opsi["bits"])
        faktor = [2, q]
        g = None
    else:
        p, g = P_DEFAULT, G_DEFAULT

    judul("STUDI KASUS: PENGIRIMAN TOKEN PRESENSI RAHASIA")
    print("  Alice (ketua kelas) ingin mengirim token presensi kepada Bob lewat grup")
    print("  chat kelas. Grup itu terbuka, jadi Eve (penyadap) bisa membaca semua pesan.")
    print("  Bagian A: Alice & Bob menyepakati kunci rahasia dengan Diffie-Hellman.")
    print("  Bagian B: Alice mengirim token presensi terenkripsi dengan ElGamal.")

    p, g = siapkan_parameter(p, g, faktor)
    try:
        bagian_diffie_hellman(p, g, a, b)
        berhasil = bagian_elgamal(p, g, pesan, x)
    except ValueError as galat:
        sys.exit(f"\n  Kesalahan: {galat}")

    judul("RINGKASAN")
    print(f"  {'Nilai':<28}| {'Alice':^7}| {'Bob':^7}| {'Eve':^7}")
    print(f"  {'-' * 28}+{'-' * 8}+{'-' * 8}+{'-' * 8}")
    baris = [
        ("Parameter p, g", "tahu", "tahu", "tahu"),
        ("Kunci privat DH a", "tahu", "-", "-"),
        ("Kunci privat DH b", "-", "tahu", "-"),
        ("Kunci publik DH A, B", "tahu", "tahu", "tahu"),
        ("Kunci bersama DH K", "tahu", "tahu", "-"),
        ("Kunci publik ElGamal y", "tahu", "tahu", "tahu"),
        ("Kunci privat ElGamal x", "-", "tahu", "-"),
        ("Bilangan acak k", "tahu", "-", "-"),
        ("Ciphertext (c1, c2)", "tahu", "tahu", "tahu"),
        ("Pesan asli", "tahu", "tahu", "-"),
    ]
    for nama, al, bo, ev in baris:
        print(f"  {nama:<28}| {al:^7}| {bo:^7}| {ev:^7}")
    print(f"\n  Status akhir: {'SEMUA TAHAP BERHASIL' if berhasil else 'ADA KESALAHAN'}")
    print("  (Eve hanya tahu semuanya jika p kecil, lihat Tahap 6.)")


if __name__ == "__main__":
    main()

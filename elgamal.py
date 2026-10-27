"""
elgamal.py
Tahapan kriptosistem ElGamal, masing-masing satu fungsi.

  Tahap 1  Pembangkitan kunci   x acak, y = g^x mod p
                                kunci publik (p, g, y), kunci privat x
  Tahap 2  Konversi pesan       teks -> byte -> blok angka m (1 <= m < p)
  Tahap 3  Enkripsi per blok    k acak, c1 = g^k mod p, c2 = m * y^k mod p
  Tahap 4  Dekripsi per blok    s = c1^x mod p, m = c2 * s^-1 mod p
  Tahap 5  Konversi balik       blok angka -> byte -> teks
"""

from matematika import acak_rentang, invers_modulo, pangkat_modulo


# ---------------------------------------------------------------------------
# Tahap 1: pembangkitan kunci
# ---------------------------------------------------------------------------

def bangkitkan_kunci(p, g, x=None, jejak=None):
    """Mengembalikan (kunci_publik, kunci_privat) dalam bentuk dict."""
    if x is None:
        x = acak_rentang(2, p - 2)
    if not 2 <= x <= p - 2:
        raise ValueError("Kunci privat x harus berada di rentang [2, p-2]")
    y = pangkat_modulo(g, x, p, jejak)
    kunci_publik = {"p": p, "g": g, "y": y}
    kunci_privat = {"p": p, "x": x}
    return kunci_publik, kunci_privat


# ---------------------------------------------------------------------------
# Tahap 2 & 5: konversi teks <-> blok angka
# ---------------------------------------------------------------------------

def ukuran_blok(p):
    """Jumlah byte per blok agar setiap nilai blok (+1) selalu < p."""
    ukuran = (p.bit_length() - 1) // 8
    if ukuran < 1:
        raise ValueError("p terlalu kecil, minimal p > 256 agar 1 byte muat")
    return ukuran


def teks_ke_blok(teks, p):
    """Mengubah teks menjadi daftar angka m (1 <= m < p).

    Teks diubah ke byte UTF-8 lalu dipotong per `ukuran_blok(p)` byte.
    Setiap potongan dijadikan bilangan lalu ditambah 1 supaya tidak pernah 0
    (m = 0 akan menghasilkan c2 = 0 sehingga pesan bocor).
    Mengembalikan (daftar_m, panjang_byte).
    """
    data = teks.encode("utf-8")
    ukuran = ukuran_blok(p)
    sisa = len(data) % ukuran
    if sisa:
        data_pad = data + b"\x00" * (ukuran - sisa)
    else:
        data_pad = data
    daftar_m = []
    for i in range(0, len(data_pad), ukuran):
        potongan = data_pad[i:i + ukuran]
        daftar_m.append(int.from_bytes(potongan, "big") + 1)
    return daftar_m, len(data)


def blok_ke_teks(daftar_m, panjang_byte, p):
    """Kebalikan teks_ke_blok."""
    ukuran = ukuran_blok(p)
    data = b""
    for m in daftar_m:
        data += (m - 1).to_bytes(ukuran, "big")
    return data[:panjang_byte].decode("utf-8")


# ---------------------------------------------------------------------------
# Tahap 3: enkripsi
# ---------------------------------------------------------------------------

def enkripsi_blok(m, kunci_publik, k=None):
    """Mengenkripsi satu blok m. Mengembalikan dict berisi k, s, c1, c2.

    k adalah bilangan acak sekali pakai dan WAJIB berbeda untuk setiap blok.
    """
    p, g, y = kunci_publik["p"], kunci_publik["g"], kunci_publik["y"]
    if not 1 <= m < p:
        raise ValueError("Blok plaintext harus berada di rentang [1, p-1]")
    if k is None:
        k = acak_rentang(2, p - 2)
    c1 = pangkat_modulo(g, k, p)        # c1 = g^k mod p
    s = pangkat_modulo(y, k, p)         # s  = y^k mod p (kunci sementara)
    c2 = (m * s) % p                    # c2 = m * s mod p
    return {"m": m, "k": k, "s": s, "c1": c1, "c2": c2}


def enkripsi_teks(teks, kunci_publik):
    """Enkripsi teks lengkap. Mengembalikan {'panjang': n, 'blok': [(c1, c2), ...]}."""
    daftar_m, panjang = teks_ke_blok(teks, kunci_publik["p"])
    blok = []
    for m in daftar_m:
        hasil = enkripsi_blok(m, kunci_publik)
        blok.append((hasil["c1"], hasil["c2"]))
    return {"panjang": panjang, "blok": blok}


# ---------------------------------------------------------------------------
# Tahap 4: dekripsi
# ---------------------------------------------------------------------------

def dekripsi_blok(c1, c2, kunci_privat, jejak_euclid=None):
    """Mendekripsi satu blok. Mengembalikan dict berisi s, s_invers, m."""
    p, x = kunci_privat["p"], kunci_privat["x"]
    if not (1 <= c1 < p and 0 <= c2 < p):
        raise ValueError("Ciphertext tidak valid")
    s = pangkat_modulo(c1, x, p)                    # s = c1^x mod p
    s_invers = invers_modulo(s, p, jejak_euclid)    # s^-1 mod p
    m = (c2 * s_invers) % p                         # m = c2 * s^-1 mod p
    return {"s": s, "s_invers": s_invers, "m": m}


def dekripsi_teks(ciphertext, kunci_privat):
    """Kebalikan enkripsi_teks."""
    daftar_m = []
    for c1, c2 in ciphertext["blok"]:
        daftar_m.append(dekripsi_blok(c1, c2, kunci_privat)["m"])
    return blok_ke_teks(daftar_m, ciphertext["panjang"], kunci_privat["p"])

# core/vpngen/keys.py
"""
Ключи для генератора конфигов — без единой зависимости.

На роутере стоит ``python3-light`` без ``cryptography``, а ``awg genkey``
или ``openssl`` есть далеко не всегда (их и ставят ради туннеля, который
мы как раз собираемся сгенерировать). Поэтому здесь три кривые на чистом
Python:

* **X25519** (RFC 7748) — ключ WireGuard/AmneziaWG. Публичный ключ уходит
  в Cloudflare при регистрации WARP, приватный — в ``[Interface]``.
* **Ed25519** (RFC 8032), только «публичный ключ из seed» — Proton VPN
  выдаёт WireGuard-доступ под сертификат на Ed25519-ключ. Приватный
  ключ WireGuard у Proton — это тот же скаляр Ed25519 (первые 32 байта
  SHA-512 от seed, «зажатые»), то есть X25519-ключ сам выводится из
  Ed25519 и на сервис уходит только публичный Ed25519.
* **P-256** (secp256r1) — ключ MASQUE. usque и mihomo ждут его в тех же
  DER-формах, что пишет Go: ``x509.MarshalECPrivateKey`` (SEC1) для
  приватного и ``x509.MarshalPKIXPublicKey`` (SPKI) для публичного.

Реализации не константны по времени: ключ генерируется один раз на
устройстве самого пользователя, и сторонний наблюдатель за временем
вычисления здесь не предусмотрен. Подписывать этим кодом ничего нельзя —
подписи и не нужны: Cloudflare и Proton достаточно публичного ключа.

Все три сверены с тест-векторами (``tests/test_vpngen_keys.py``), а
DER-формы — с разбором ``cryptography``, когда она установлена.
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ─────────────────────────────── X25519 ──────────────────────────────

_P25519 = 2 ** 255 - 19
_A24 = 121665


def _clamp(k: bytes) -> int:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    """Умножение точки Монтгомери (RFC 7748 §5)."""
    if len(scalar) != 32 or len(u) != 32:
        raise ValueError("X25519: нужны 32-байтные скаляр и точка")
    p = _P25519
    k = _clamp(scalar)
    ub = bytearray(u)
    ub[31] &= 127
    x1 = int.from_bytes(ub, "little")
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) * (da + cb) % p
        z3 = x1 * (da - cb) * (da - cb) % p
        x2 = aa * bb % p
        z2 = e * (aa + _A24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


_X25519_BASE = (9).to_bytes(32, "little")


def x25519_public(private: bytes) -> bytes:
    return x25519(private, _X25519_BASE)


def x25519_keypair() -> tuple:
    """``(private_b64, public_b64)`` — пара WireGuard."""
    priv = bytearray(secrets.token_bytes(32))
    # Зажимаем сразу: так ключ совпадает с тем, что выдал бы `wg genkey`,
    # и не зависит от того, зажмёт ли его потребитель.
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv = bytes(priv)
    return b64(priv), b64(x25519_public(priv))


def wg_public_from_private(private_b64: str) -> str:
    raw = base64.b64decode(private_b64)
    if len(raw) != 32:
        raise ValueError("приватный ключ WireGuard — 32 байта в base64")
    return b64(x25519_public(raw))


# ─────────────────────────────── Ed25519 ─────────────────────────────

_ED_D = (-121665 * pow(121666, _P25519 - 2, _P25519)) % _P25519
_ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_ED_B = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _P25519)


def _ed_add(pt, qt):
    p = _P25519
    x1, y1, z1, t1 = pt
    x2, y2, z2, t2 = qt
    a = (y1 - x1) * (y2 - x2) % p
    b = (y1 + x1) * (y2 + x2) % p
    c = t1 * 2 * _ED_D * t2 % p
    d = z1 * 2 * z2 % p
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _ed_mul(k: int, pt):
    acc = (0, 1, 1, 0)                       # нейтральный элемент
    while k:
        if k & 1:
            acc = _ed_add(acc, pt)
        pt = _ed_add(pt, pt)
        k >>= 1
    return acc


def _ed_encode(pt) -> bytes:
    p = _P25519
    x, y, z, _ = pt
    zi = pow(z, p - 2, p)
    x, y = x * zi % p, y * zi % p
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def ed25519_public(seed: bytes) -> bytes:
    """Публичный ключ Ed25519 из 32-байтного seed (RFC 8032 §5.1.5)."""
    if len(seed) != 32:
        raise ValueError("Ed25519: seed — 32 байта")
    h = hashlib.sha512(seed).digest()
    return _ed_encode(_ed_mul(_clamp(h[:32]), _ED_B))


def proton_keypair() -> dict:
    """Ключи для Proton VPN.

    ``ed25519_pem`` уходит сервису (Proton подписывает на него сертификат),
    ``wg_private`` — в ``[Interface] PrivateKey``. Это один и тот же
    скаляр: X25519-ключ получается из Ed25519 так же, как у клиента
    Proton, поэтому сервер узнаёт нас по WireGuard-ключу, который мы ему
    никогда не отправляли.
    """
    seed = secrets.token_bytes(32)
    pub = ed25519_public(seed)
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    wg_priv = bytes(h)
    # SPKI Ed25519: SEQUENCE{ SEQUENCE{ OID 1.3.101.112 }, BIT STRING }.
    spki = bytes.fromhex("302a300506032b6570032100") + pub
    pem = ("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n"
           % b64(spki))
    return {
        "ed25519_public": b64(pub),
        "ed25519_pem": pem,
        "wg_private": b64(wg_priv),
        "wg_public": b64(x25519_public(wg_priv)),
    }


# ─────────────────────────────── P-256 ───────────────────────────────

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _jac_double(pt):
    p = _P256_P
    x, y, z = pt
    if not y:
        return (0, 1, 0)
    yy = y * y % p
    s = 4 * x * yy % p
    zz = z * z % p
    m = 3 * (x - zz) * (x + zz) % p           # a = -3
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * yy * yy) % p
    z3 = 2 * y * z % p
    return (x3, y3, z3)


def _jac_add(pt, qt):
    p = _P256_P
    x1, y1, z1 = pt
    x2, y2, z2 = qt
    if not z1:
        return qt
    if not z2:
        return pt
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    if u1 == u2:
        return _jac_double(pt) if s1 == s2 else (0, 1, 0)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    z3 = h * z1 * z2 % p
    return (x3, y3, z3)


def p256_mul(k: int, point=_P256_G) -> tuple:
    """``k·point`` в аффинных координатах."""
    acc = (0, 1, 0)
    pt = (point[0], point[1], 1)
    while k:
        if k & 1:
            acc = _jac_add(acc, pt)
        pt = _jac_double(pt)
        k >>= 1
    x, y, z = acc
    if not z:
        raise ValueError("P-256: бесконечно удалённая точка")
    p = _P256_P
    zi = pow(z, p - 2, p)
    zi2 = zi * zi % p
    return (x * zi2 % p, y * zi2 * zi % p)


def p256_on_curve(x: int, y: int) -> bool:
    p = _P256_P
    return (y * y - (x * x * x - 3 * x + _P256_B)) % p == 0


# OID prime256v1 = 1.2.840.10045.3.1.7, id-ecPublicKey = 1.2.840.10045.2.1
_OID_P256 = bytes.fromhex("06082a8648ce3d030107")
_OID_EC = bytes.fromhex("06072a8648ce3d0201")


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def p256_keypair() -> dict:
    """Ключи MASQUE в формах Go x509.

    ``private_der_b64`` — SEC1 ECPrivateKey (поле ``private_key`` у usque
    и mihomo), ``public_der_b64`` — SPKI (уходит в Cloudflare при
    переключении устройства на MASQUE).
    """
    d = secrets.randbelow(_P256_N - 1) + 1
    x, y = p256_mul(d)
    point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    sec1 = _der(0x30, b"".join((
        _der(0x02, b"\x01"),                        # version 1
        _der(0x04, d.to_bytes(32, "big")),          # privateKey
        _der(0xA0, _OID_P256),                      # [0] parameters
        _der(0xA1, _der(0x03, b"\x00" + point)),    # [1] publicKey
    )))
    spki = _der(0x30, _der(0x30, _OID_EC + _OID_P256)
                + _der(0x03, b"\x00" + point))
    return {"private_der_b64": b64(sec1), "public_der_b64": b64(spki)}


def pem_body(text: str) -> str:
    """Base64 из PEM без заголовков (``-----BEGIN …-----``).

    Cloudflare отдаёт ключ MASQUE-сервера PEM'ом; usque хранит его так,
    а mihomo ждёт голый base64 SPKI.
    """
    lines = [ln.strip() for ln in str(text or "").splitlines()]
    body = "".join(ln for ln in lines if ln and not ln.startswith("-----"))
    return body

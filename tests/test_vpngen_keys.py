# tests/test_vpngen_keys.py
"""Ключи генератора конфигов: тест-векторы RFC/NIST и формы DER как у Go.

На роутере нет `cryptography`, поэтому кривые написаны на чистом Python
(core/vpngen/keys.py). Здесь они сверяются с опубликованными векторами,
а DER — с разбором `cryptography`, если она есть в окружении тестов.
"""

import base64
import unittest

from core.vpngen import keys

try:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    HAVE_CRYPTO = True
except ImportError:                                  # pragma: no cover
    HAVE_CRYPTO = False


class TestX25519(unittest.TestCase):

    def test_rfc7748_alice(self):
        priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645"
                             "df4c2f87ebc0992ab177fba51db92c2a")
        self.assertEqual(keys.x25519_public(priv).hex(),
                         "8520f0098930a754748b7ddcb43ef75a"
                         "0dbf3a0d26381af4eba4a98eaa9b4e6a")

    def test_rfc7748_shared_secret(self):
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645"
                          "df4c2f87ebc0992ab177fba51db92c2a")
        b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece43537"
                              "3f8343c85b78674dadfc7e146f882b4f")
        self.assertEqual(keys.x25519(a, b_pub).hex(),
                         "4a5d9d5ba4ce2de1728e3bf480350f25"
                         "e07e21c947d19e3376f09b3c1e161742")

    def test_keypair_is_clamped_and_consistent(self):
        priv, pub = keys.x25519_keypair()
        raw = base64.b64decode(priv)
        self.assertEqual(raw[0] & 7, 0)
        self.assertEqual(raw[31] & 0xC0, 0x40)
        self.assertEqual(keys.wg_public_from_private(priv), pub)

    @unittest.skipUnless(HAVE_CRYPTO, "нет cryptography")
    def test_matches_reference_implementation(self):
        priv, pub = keys.x25519_keypair()
        ref = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
        self.assertEqual(
            keys.b64(ref.public_key().public_bytes(ser.Encoding.Raw,
                                                   ser.PublicFormat.Raw)),
            pub)


class TestEd25519(unittest.TestCase):

    def test_rfc8032_test1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                             "4449c5697b326919703bac031cae7f60")
        self.assertEqual(keys.ed25519_public(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a"
                         "0ee172f3daa62325af021a68f707511a")

    def test_proton_wireguard_key_is_the_edwards_scalar(self):
        """X25519-ключ Proton — тот же скаляр, что у Ed25519.

        Проверяем через бирациональное отображение: u = (1+y)/(1-y) от
        публичного Ed25519 обязано совпасть с X25519-публичным ключом.
        Иначе Proton не узнал бы нас по WireGuard-ключу.
        """
        pair = keys.proton_keypair()
        ed = bytearray(base64.b64decode(pair["ed25519_public"]))
        ed[31] &= 0x7F
        p = 2 ** 255 - 19
        y = int.from_bytes(ed, "little")
        u = (1 + y) * pow(1 - y, p - 2, p) % p
        self.assertEqual(keys.b64(u.to_bytes(32, "little")),
                         pair["wg_public"])

    def test_pem_is_spki_ed25519(self):
        pair = keys.proton_keypair()
        self.assertIn("BEGIN PUBLIC KEY", pair["ed25519_pem"])
        der = base64.b64decode(keys.pem_body(pair["ed25519_pem"]))
        self.assertEqual(der[:12].hex(), "302a300506032b6570032100")
        self.assertEqual(keys.b64(der[12:]), pair["ed25519_public"])
        # Приватный ключ в PEM не попадает ни в каком виде.
        self.assertNotIn(pair["wg_private"], pair["ed25519_pem"])

    def test_wg_private_derivation(self):
        pair = keys.proton_keypair()
        raw = base64.b64decode(pair["wg_private"])
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[0] & 7, 0)


class TestP256(unittest.TestCase):

    def test_rfc6979_public_key(self):
        d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        x, y = keys.p256_mul(d)
        self.assertEqual(x, 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6)
        self.assertEqual(y, 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
        self.assertTrue(keys.p256_on_curve(x, y))

    def test_der_shapes_match_go(self):
        """SEC1 121 байт (164 символа base64, как у usque), SPKI 91 байт."""
        pair = keys.p256_keypair()
        sec1 = base64.b64decode(pair["private_der_b64"])
        spki = base64.b64decode(pair["public_der_b64"])
        self.assertEqual(len(sec1), 121)
        self.assertEqual(len(pair["private_der_b64"]), 164)
        self.assertEqual(len(spki), 91)
        self.assertEqual(sec1[:7].hex(), "30770201010420")
        self.assertEqual(spki[:27].hex(),
                         "3059301306072a8648ce3d020106082a8648ce3d03010703420004")
        self.assertEqual(sec1[-65:], spki[-65:])

    @unittest.skipUnless(HAVE_CRYPTO, "нет cryptography")
    def test_der_parsed_by_reference(self):
        pair = keys.p256_keypair()
        priv = ser.load_der_private_key(
            base64.b64decode(pair["private_der_b64"]), None)
        pub = ser.load_der_public_key(base64.b64decode(pair["public_der_b64"]))
        self.assertEqual(priv.public_key().public_numbers(),
                         pub.public_numbers())

    def test_pem_body(self):
        pem = "-----BEGIN PUBLIC KEY-----\nAAA\nBBB\n-----END PUBLIC KEY-----\n"
        self.assertEqual(keys.pem_body(pem), "AAABBB")


if __name__ == "__main__":
    unittest.main()

import base64
import binascii
from binascii import hexlify

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hashlib import sha256

def save_file(name, data):
    with open(name, 'w') as file:
        file.write(data)


def save_data_needs_to_be_send_to_Alice_to_file(bob_sign_pub_key, y, signature):
    string_PEM = bob_sign_pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode(encoding="UTF-8")

    result_str = "bob_sign_pub_key: \n\n " + string_PEM + "\n"
    result_str += "y: \n " + y + "\n" + "\n"
    result_str += "signature: \n " + signature

    save_file("alice_data.txt", result_str)


EC_TYPE = ec.SECP256K1()


# Відкритий ключ Alice для підпису (довгостроковий) у форматі PEM (алгоритм ECDSA з кривою SECP256K1 та хеш-функцією SHA-256):
#
# -----BEGIN PUBLIC KEY-----
# MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
# HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
# -----END PUBLIC KEY-----

alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""

alice_pub_sign_key = serialization.load_pem_public_key(alice_pub_sign_key_raw)
print("is it ec public key? ", isinstance(alice_pub_sign_key, ec.EllipticCurvePublicKey))
print("ec public key curve is ec.SECP256K1? ", isinstance(alice_pub_sign_key.curve, ec.SECP256K1))

# Відкритий ключ Alice для узгодження ключа (значення x = xP), згенерований алгоритмом X25519, закодований використовуючи функцію hexlify:
alice_x_pub_key = b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433'
alice_x_pub_key_unhex = binascii.unhexlify(alice_x_pub_key)
loaded_alice_x_pub_key = x25519.X25519PublicKey.from_public_bytes(alice_x_pub_key_unhex)

# Підпис відкритого ключа Alice для узгодження ключа (для перевірки автентичності), створений алгоримом ECDSA на кривій SECP256K1 та хеш-функції SHA-256,
# закодований використовуючи функцію hexlify (включає обидва значення {r, s}):
signature = b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'
signature_unhex = binascii.unhexlify(signature)


# ----------------------------------------------------------

# Необхідно:
# 1. Згенерувати довгострокову ключову пару для підпису алгоритмом ECDSA на кривій SECP256K1.

bob_private_key = ec.generate_private_key(EC_TYPE)

bob_public_key = bob_private_key.public_key()

# 2. Згенерувати приватний ключ боба для узгодження ключа алгоритмом X25519.

bob_y_private_key = X25519PrivateKey.generate()


# 3. Перевірити підпис відкритого ключа Alice для узгодження ключа (використовуючи відкритий ключ Alice для підпису).


alice_pub_sign_key.verify(signature_unhex, alice_x_pub_key_unhex, ec.ECDSA(hashes.SHA256())) # damn, I lost here like 2 hours before I realised that signature is also hex encoded

# 4. Створити відкритий ключ ECDH (значення Y = yP) для надсилання Alice

bob_y_pub_key = bob_y_private_key.public_key()

# 5. Cтворити підпис значення Y використовуючи приватний довгостроковий ключ Боба для підпису.

shared_key = bob_y_private_key.exchange(loaded_alice_x_pub_key)




# * Результатом вашого завдання повинні бути 3 згенеровані значення для надсилання Alice:
# 1. Відкритий довгостроковий ключ підпису Боба у форматі PEM.
# 2. Відкритий ключ ECDH (значення Y = yP з боку Боба) у форматі hex.
# 3. Підпис відкритого ключа ECDH у форматі hex.

bob_y_pub_key_hex = binascii.hexlify(bob_y_pub_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
))

signature = bob_private_key.sign(
    bob_y_pub_key_hex,
    ec.ECDSA(hashes.SHA256())
)

signature = binascii.hexlify(signature) # haha, now Alice will suffer too

save_data_needs_to_be_send_to_Alice_to_file(bob_public_key, bob_y_pub_key_hex.decode("UTF-8"), signature.decode("UTF-8"))

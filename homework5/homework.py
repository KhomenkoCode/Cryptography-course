import binascii
from binascii import hexlify

import requests
import json
import codecs



############################ TASK #1

# Passwords
#    qwertyuiop
#    sofPed-westag-jejzo1
#    f3Fg#Puu$EA1mfMx2
#    TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh

# we working w/ user set passwords, not hashes generated by CSPRNG so entropy is low
# so we need to use PBKDF
# I will use Argon2id for this case following OWASP recomendations
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# Use Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism.



import argon2
from argon2.profiles import RFC_9106_LOW_MEMORY

ph = argon2.PasswordHasher(
    time_cost=RFC_9106_LOW_MEMORY.time_cost, # 3 iterations
    memory_cost=RFC_9106_LOW_MEMORY.memory_cost, # 64 MiB
    parallelism=RFC_9106_LOW_MEMORY.parallelism, # 4 threads
    hash_len=RFC_9106_LOW_MEMORY.hash_len, # 32 bytes
    salt_len=RFC_9106_LOW_MEMORY.salt_len # 16 bytes
)

# 64 MiB = 2^20; 1 GB of memory = 2^30
# 2^30 - 2^20 = 1.072693248 × 10^9
# we are able to process 1 000 000 000 passwords w/ just 1 GB of memory

def password_hash(password):
  hash = ph.hash(password)
  print("----------------")
  print("pass = " + password)
  print("hash = " + hash)
  print("verification ", ph.verify(hash, password))
  with open('task1.txt', 'a') as f:
    f.write(hash+'\n')
  return hash

password_hash("qwertyuiop")
password_hash("sofPed-westag-jejzo1")
password_hash("f3Fg#Puu$EA1mfMx2")
password_hash("TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh")


############################ TASK #2


# Згенерувати імітовставку (Message Authentication Code, MAC) для наданого шифротексту.
#
# Головний ключ, використаний для зашифрування:
key = "63e353ae93ecbfe00271de53b6f02a46"
# Шифротекст:
ct = "76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a"
# IV:
iv = "75b777fc8f70045c6006b39da1b3d622"


# i will use HKDF-SHA256 as the most secure way to generate MAC
# also because we have a algorithm that uses IV and maybe we can make use of it in here

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


hkdf = HKDF(
     algorithm=hashes.SHA256(),
     length=32,
     salt=iv.encode(encoding="utf-8"), # iv and salt is having the same structure, basically rand byte value so we will use it here
     info=key.encode(encoding="utf-8"), # privately passed to receiver, in this case to crack MAC you will need both encoding key & iv
     backend=default_backend()
)
ct_bytes = ct.encode(encoding="utf-8")

mac = hkdf.derive(ct_bytes)

with open('task2.txt', 'a') as f:
  f.write(binascii.hexlify(mac).decode(encoding="utf-8")) # FYI: I get 5 years older by amount of rage I experienced trying to figure out how to decode this crap

# hkdf object is one time use, so to check if it works we will need to create it once more
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=iv.encode(encoding="utf-8"),
    info=key.encode(encoding="utf-8"),
    backend=default_backend()
)

hkdf.verify(ct_bytes, mac) # no exception InvalidKey raised


############################ TASK #3
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import os

# we need to create AES encrytion key from username and pass
# key specs https://datatracker.ietf.org/doc/html/rfc3826#section-3.1.2.1
# key length: 128 bit / 8 = 32 symbols
# key value should not repeat for users w/ the same password
# same as task #1: we working w/ user set passwords, not hashes generated by CSPRNG so entropy is low
# but AES key need to be max effective entropy
# we can actually use same PBKDF Argon2id from task 1 to do it


def derive_key(username, password, some_salt_stored_in_DB):
  hash = argon2.hash_password_raw(
      time_cost=RFC_9106_LOW_MEMORY.time_cost,
      memory_cost=RFC_9106_LOW_MEMORY.memory_cost,
      parallelism=RFC_9106_LOW_MEMORY.parallelism,
      hash_len=16,
      password=password.encode(encoding="utf-8"),
      salt=some_salt_stored_in_DB,
      type=argon2.low_level.Type.ID)
  print("Argon2 raw hash:", binascii.hexlify(hash))
  print("HASH LEGTH: ", len(hash))
  return hash


some_salt_previously_generated = os.urandom(16) # we should get it from DB or JSON as mentioned in Task
key = derive_key("user1", "qwerty12345", some_salt_previously_generated)

# lets try encrypt using this hash using AES-128
IV = os.urandom(16)
encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
text = 'LETS TRY ENCRYPT THIS'
msg_padded = pad(text.encode(), AES.block_size)
ciphertext = encryptor.encrypt(msg_padded)
print("encrypted text:: ", binascii.hexlify(ciphertext).upper())
# no error occured
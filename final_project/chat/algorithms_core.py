import binascii
import base64
import hmac
import hashlib
from Crypto.Cipher import AES

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

def generate_ec225519_private_key():
  return X25519PrivateKey.generate()


def finalize_ec_key(generated_private_key, received_public_key): # return hex string, so we will always operate str
  key = generated_private_key.exchange(received_public_key)
  return binascii.hexlify(key).decode("UTF-8")


# auth and KDF at the same time
def sign_hmac_sha256(message, key):
  return hmac.new(
      binascii.unhexlify(key.encode("UTF-8")),
      msg=message.encode("UTF-8"),
      digestmod=hashlib.sha256
  ).hexdigest().upper()

def validate_hmac_sha256(message, key, sign):
  return sign_hmac_sha256(message, key) == sign


class AES_pkcs5:
  def __init__(self,key:str, mode:AES.MODE_ECB=AES.MODE_CBC,block_size:int=16):
    self.key = self.setKey(key)
    self.mode = mode
    self.block_size = block_size

  def pad(self,byte_array:bytearray):
    """
    pkcs5 padding
    """
    pad_len = self.block_size - len(byte_array) % self.block_size
    return byte_array + (bytes([pad_len]) * pad_len)

  # pkcs5 - unpadding
  def unpad(self,byte_array:bytearray):
    return byte_array[:-ord(byte_array[-1:])]


  def setKey(self,key:str):
    # convert to bytes
    key = key.encode('utf-8')
    # get the sha1 method - for hashing
    sha1 = hashlib.sha1
    # and use digest and take the last 16 bytes
    key = sha1(key).digest()[:16]
    # now zero pad - just incase
    key = key.zfill(16)
    return key

  def encrypt(self,message:str)->str:
    # convert to bytes
    byte_array = message.encode("UTF-8")
    # pad the message - with pkcs5 style
    padded = self.pad(byte_array)
    # new instance of AES with encoded key
    cipher = AES.new(self.key, AES.MODE_ECB)
    # now encrypt the padded bytes
    encrypted = cipher.encrypt(padded)
    # base64 encode and convert back to string
    return base64.b64encode(encrypted).decode('utf-8')

  def decrypt(self,message:str)->str:
    # convert the message to bytes
    byte_array = message.encode("utf-8")
    # base64 decode
    message = base64.b64decode(byte_array)
    # AES instance with the - setKey()
    cipher= AES.new(self.key, AES.MODE_ECB)
    # decrypt and decode
    decrypted = cipher.decrypt(message).decode('utf-8')
    # unpad - with pkcs5 style and return
    return self.unpad(decrypted)



class Ratchet:
  rootKey = None

  def __init__(self, rootKey):
    self.rootKey = rootKey

  def rotate(self, input):
    hash = sign_hmac_sha256(input, self.rootKey)
    self.rootKey = hash[:32]
    return hash[32:]



ALICE_INPUT_RATCHET_CONST = BOB_OUTPUT_RATCHET_CONST = "DE8D1A985D03F9D63A522334CE5F2B5A"
BOB_INPUT_RATCHET_CONST = ALICE_OUTPUT_RATCHET_CONST = "AF9EADB3D02815B6DEC218633FE62598"

class DoubleRatchet:

  def __init__(self, rootKey, inputRatchet_input_const, outputRatchet_input_const):
    self.rootRatchet = Ratchet(rootKey)
    self.inputRatchet = None
    self.outputRatchet = None
    self.inputRatchet_input_const = inputRatchet_input_const
    self.outputRatchet_input_const = outputRatchet_input_const

  def rotate_root(self, dh_shared_key):
    return self.rootRatchet.rotate(dh_shared_key)

  def get_new_input_ratchet_key(self, rotated_root_key):
    self.inputRatchet = Ratchet(rotated_root_key)
    return self.inputRatchet.rotate(self.inputRatchet_input_const)

  def get_new_output_ratchet_key(self, rotated_root_key):
    self.outputRatchet = Ratchet(rotated_root_key)
    return self.outputRatchet.rotate(self.outputRatchet_input_const)



# recieve
# get pub
# generate private
# pr X pub = shared
# send pub

# send
# generate private

def pub_key_into_str(ec_public_key):
  return ec_public_key.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo,
  ).decode(encoding="UTF-8")

def create_X22519PubKey_form_str(pub_key_str):
  return serialization.load_pem_public_key(pub_key_str)




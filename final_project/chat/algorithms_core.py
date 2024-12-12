import binascii
import base64
import hmac
import hashlib
import uuid

from Crypto.Cipher import AES

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


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


def pub_key_into_str(ec_public_key):
  return ec_public_key.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo,
  ).decode(encoding="UTF-8")


def create_X22519PubKey_form_str(pub_key_str):
  return serialization.load_pem_public_key(pub_key_str)


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


class DHRatchetKeyStorage:

  def __init__(self, generated_private_key, received_pub_key):
    self.myPrivateKey = generated_private_key
    self.receivedPubKey = received_pub_key

  def get_my_pub_key(self):
    return self.myPrivateKey.public_key()

  def generate_shared_key(self):
    return finalize_ec_key(self.myPrivateKey, self.receivedPubKey)

  def new_shared_key(self):
    self.myPrivateKey = generate_ec225519_private_key();
    return self.generate_shared_key()

  def get_shared_key_by_new_pub_key(self, new_received_pub_key):
    self.receivedPubKey = new_received_pub_key
    return self.generate_shared_key()


class DiffieHellmanDoubleRatchet:

  def __init__(self, init_private_key, received_public_key, inputRatchet_input_const, outputRatchet_input_const):
    self.diffie_hellman_key_storage = DHRatchetKeyStorage(init_private_key, received_public_key)
    self.double_ratchet = DoubleRatchet(
        self.diffie_hellman_key_storage.generate_shared_key(),
        inputRatchet_input_const,
        outputRatchet_input_const
    )

  def get_input_ratchet_key(self, received_pub_key):
    shared = self.diffie_hellman_key_storage.get_shared_key_by_new_pub_key(received_pub_key)
    return self.double_ratchet.get_new_input_ratchet_key(shared)

  def get_output_ratchet_key(self):
    shared = self.diffie_hellman_key_storage.new_shared_key() # NEW PRIVATE KEY GENERATION
    return self.double_ratchet.get_new_output_ratchet_key(shared)

  def get_current_public_key_to_send(self):
    return self.diffie_hellman_key_storage.get_my_pub_key()

# ALGORITHM TEST

# ALICE_INPUT_RATCHET_CONST = BOB_OUTPUT_RATCHET_CONST = "DE8D1A985D03F9D63A522334CE5F2B5A"
# BOB_INPUT_RATCHET_CONST = ALICE_OUTPUT_RATCHET_CONST = "AF9EADB3D02815B6DEC218633FE62598"
#
# alice_initPK = generate_ec225519_private_key()
#
# bob_initPK = generate_ec225519_private_key()
# alice_initPubK = alice_initPK.public_key()
#
# bob_initPubK = bob_initPK.public_key()
#
#
# alice_dhdr = DiffieHellmanDoubleRatchet(alice_initPK, bob_initPubK, ALICE_INPUT_RATCHET_CONST, ALICE_OUTPUT_RATCHET_CONST)
# bob_dhdr = DiffieHellmanDoubleRatchet(bob_initPK, alice_initPubK, BOB_INPUT_RATCHET_CONST, BOB_OUTPUT_RATCHET_CONST)
#
# a_in = alice_dhdr.get_output_ratchet_key()
# b_out = bob_dhdr.get_input_ratchet_key(alice_dhdr.get_current_public_key_to_send())
#
# print(f"a_in {a_in} b_out {b_out}")
#
# a_in = alice_dhdr.get_output_ratchet_key()
# b_out = bob_dhdr.get_input_ratchet_key(alice_dhdr.get_current_public_key_to_send())
#
# print(f"a_in {a_in} b_out {b_out}")
#
# b_in = bob_dhdr.get_output_ratchet_key()
# a_out = alice_dhdr.get_input_ratchet_key(bob_dhdr.get_current_public_key_to_send())
#
# print(f"b_in {b_in} b_out {a_out}")
#
#
# b_in = bob_dhdr.get_output_ratchet_key()
# a_out = alice_dhdr.get_input_ratchet_key(bob_dhdr.get_current_public_key_to_send())
#
# print(f"b_in {b_in} b_out {a_out}")

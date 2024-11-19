from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto.Util.number import bytes_to_long, long_to_bytes

public_key_file = "task_pub.pem"  # – відкритий ключ RSA лектора.
ct_message_file = "task_message.txt"  # – файл з повідомленням.
signature_file = "task_signature.txt"  # – файл з підписом RSA, згенерованим приватним ключем лектора.


def read_file(filename):
  with open(filename, "r") as msg_file:
    text = msg_file.read()
    # print(filename, " = ", text)
  return text

def save_file(name, data):
  with open(name, 'w') as file:
    file.write(data)

def load_public_key(filename):
  with open(filename, 'rb') as pem_in:
    pemlines = pem_in.read()
  key = load_pem_public_key(pemlines, None)
  return key



#################################### Завдання 3

n = 89130176363968657187562046515332781879906710777886742664996031757940362853930049819009596594982246571669482031940134479813793328701373238273415076270891142859666516439231904521557755729322490606876589914024096621194962329718893576886641536066926542462448229133783052051407061075447588804617825930836181625077
e = 1
# Okay, wtf
# it's not even encrypted
# decryption process is basically: m^1 (mod 89130176363...)
# which is the original message

ct = 9525146106593233668246438912833048755472216768584708733

decrypted = long_to_bytes(ct)
print(decrypted) # b'crypto{saltstack_power}'


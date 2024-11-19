from math import sqrt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto.Util.number import bytes_to_long, long_to_bytes
from decimal import *


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

n = 30460296206281253605887131667441042408833105116654370140736576080711297109384941590369941855116386695157474206375705248890458232777575365270780855265861075198881090190505284920581410885950363830131451127387018904728639607372668753109249046707840464876881594185896506371262697868257217488062754637361594352910022190227237953540282162231147699265142164623465337280610190892470279654386272723760887111753067292988287956381022028725288845603024605833650847697724636088418782911705757980221361510892370739837402705040814150778298018509675199917931423568797098139493145394232981571448400646089157848498064505852923746440139
e = 3
ct = 183001753190025751114220069887230720857448492282044619321040127443487542179613757444809112210217896463899655491288132907560322811734646233820773


# d = pow(e, -1)
getcontext().prec = 100 # float precision is 100 numbers after dot
d = Decimal(1) / Decimal(e)
print("",d)
ct = round(pow(ct, d))
print(ct)

decrypted = long_to_bytes(ct)
print(decrypted) # b'crypto{robot_dreams}'


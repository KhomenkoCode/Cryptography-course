from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

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

ct_message = bytes.fromhex(read_file(ct_message_file))
public_pem_txt = read_file(public_key_file)
signature = bytes.fromhex(read_file(signature_file))

#################################### Завдання 1
# Використовуючи наданий відкритий ключ, повідомлення та підпис, перевірити автентичність підпису.
# Для створення підпису була використана схема RSA-PSS з алгоритмом хешування SHA-256.

public_key = load_public_key(public_key_file)

public_key.verify(
    signature,
    ct_message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), # була використана схема RSA-PSS
    hashes.SHA256(),
)

# no exception was thrown, verification is successful


#################################### Завдання 2

text_to_encrypt = b"Never gonna give you up \
Never gonna let you down\
Never gonna run around and desert you\
Never gonna make you cry\
Never gonna say goodbye\
Never gonna tell a lie and hurt you"

filename = "task-2-message.txt"

# we will use RSA-OAEP
ciphertext = public_key.encrypt(
    text_to_encrypt,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

print(ciphertext.hex())

save_file(filename, ciphertext.hex())


#################################### Завдання 3

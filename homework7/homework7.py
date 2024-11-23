from binascii import hexlify

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# general RSA-PSS functions
def sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("The signature is valid.")
    except:
        print("The signature is invalid.")

def dh_key_to_bytes(dh_public_key):
    return dh_public_key.public_numbers().y.to_bytes(2048 // 8, 'big')




### STEP 1 generate & exchange RSA keys

print("Alice generating RSA private & pub key pair")

alice_RSA_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
) # alice rsa private key


bob_RSA_public_key = alice_RSA_private_key.public_key()  # public key alice sent to bob via public channel

print("Alice ------------ sending RSA public Key to ------------> Bob", bob_RSA_public_key)




print("BOB generating RSA private & pub key pair")

bob_RSA_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
) # bob rsa private key

alice_RSA_public_key = bob_RSA_private_key.public_key()  # public key bob sent to alice via public channel

print("Bob ------------ sending RSA public Key to ------------> Alice", alice_RSA_public_key)


### STEP 1 generate & exchange DH keys


# Загальні параметри DH спільні для всіх учасників і узгоджуються на рівні протоколу.
print("Generating parameters...")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("\nModule:\n", parameters.parameter_numbers().p)
print("\nGen:", parameters.parameter_numbers().g)

# Alice
alice_DH_private_key = parameters.generate_private_key()  # a
alice_DH_public_key = alice_DH_private_key.public_key()  # g^a


ALICE_message_signature = sign(alice_RSA_private_key, dh_key_to_bytes(alice_DH_public_key))

print("Alice ------------ sending DH g^a to ------------> Bob", alice_DH_public_key)
print("W/ RSA signature", ALICE_message_signature)

# Bob

bob_DH_private_key = parameters.generate_private_key()  # b
bob_DH_public_key = bob_DH_private_key.public_key()  # g^b

BOB_message_signature = sign(bob_RSA_private_key, dh_key_to_bytes(bob_DH_public_key))

print("Bob ------------ sending DH g^b to ------------> Alice", bob_DH_public_key)
print("W/ RSA signature", BOB_message_signature)


# Alice --> Bob:    alice_public_key
# Bob --> Alice:    bob_public_key

print("Bob & Alice BOTH CHECKING RSA SIGNATURES (AUTH MESSAGE CHECK) ")

print("Alice is checking RSA-PSS sign")
verify(alice_RSA_public_key, BOB_message_signature, dh_key_to_bytes(bob_DH_public_key))

print("Bob is checking RSA-PSS sign")
verify(bob_RSA_public_key, ALICE_message_signature, dh_key_to_bytes(alice_DH_public_key))

print("Bob & Alice BOTH GENERATING final DH KEYS")

# Alice
alice_shared_value = alice_DH_private_key.exchange(bob_DH_public_key)
print("\nShared secret value:\n", hexlify(alice_shared_value))
alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(alice_shared_value)
print("\nDerived secret key:\n", hexlify(alice_derived_key))

# Bob
bob_shared_value = bob_DH_private_key.exchange(alice_DH_public_key)
print("\nShared secret value:\n", hexlify(bob_shared_value))
bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(bob_shared_value)

print("\nDerived secret key:\n", hexlify(bob_derived_key))
print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
print("Shared keys equal?\t", alice_derived_key == bob_derived_key)

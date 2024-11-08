import secrets

with open('csprng_secrets_randbits.bin', 'wb') as file:
    i = secrets.randbits(1000000001)
    file.write(i.to_bytes(i.bit_length(), byteorder='big', signed=False))

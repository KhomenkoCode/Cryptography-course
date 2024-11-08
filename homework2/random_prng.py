from random import randint

with open('prng_random_randint.bin', 'wb') as file:
    bitcounter=0
    while bitcounter < 1000000000:
        i = randint(0, 9)
        bitcounter+=i.bit_length()
        file.write(i.to_bytes(i.bit_length(), byteorder='big', signed=False))

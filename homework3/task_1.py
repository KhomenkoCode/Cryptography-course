from binascii import hexlify
import requests
import json
import codecs

def encrypt(pt):
    p = hexlify(pt).decode()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + p
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct

ct = encrypt("0".encode()) #1 byte
print("0".encode())
print(ct)

ct = encrypt("123456".encode()) #6 bytes
print("123456".encode())
print(ct)

ct = encrypt("1234567".encode()) #7 bytes - NEW BLOCK
print("1234567".encode())
print(ct)

#  by sending 1 byte we get 64 symbols / 2 = 32 bytes
#  at 7 bytes of info, when key is not enough it adds 32 symbols / 2 = 16 bytes block
#  so
#     1. it needs 2 blocks to render 1 byte of our info: FLAG LENGTH IS 16-31 bytes
#     2. on 7 bytes we need 3 blocks
#     3. it means that we can put 6 out of 32 bytes before overflowing
#         flag_length + 6 = 32;
#         flag_length = 32 - 6 = 26 symbols (bytes)


known_flag = ""


# в группу из 2 блоков (32 бит) будем генерировать изсестньій текст размером в 31 символ (1 неизвестньій символ в конце будет браться из флага)
# потом будем брать уже изсестньій текст и подбирать последний символ пока значения шифротектстов не совпадут


for i in range(1, 26):
    number_of_symbols_in_first_two_blocks = 32 - len(known_flag) - 1

    prefix = "0" * number_of_symbols_in_first_two_blocks

    print("prefix is "+prefix)
    print("known_flag is "+known_flag)

    ct_example = encrypt(prefix.encode())[0:64]

    # print(ct_example)
    # Перебираем не все 256 значений hex, а только печатные символьі ASCII
    for j in range(32, 127):
        symbol_in_question = chr(j)
        request = prefix + known_flag + symbol_in_question
        ct_check = encrypt(request.encode())[0:64]
        # print(symbol_in_question + "  -- " + ct_check)
        if ct_example == ct_check:
            print("symbol found!! " + symbol_in_question)
            known_flag = known_flag + symbol_in_question
            break

print("known_flag is " + known_flag)

#результат виконання flag = "crypto{p3n6u1n5_h473_3cb}"
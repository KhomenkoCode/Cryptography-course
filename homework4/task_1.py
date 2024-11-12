from binascii import hexlify
import requests
import json
import codecs


def encrypt(pt):
    p = hexlify(pt).decode()
    url = "http://aes.cryptohack.org/lazy_cbc/encrypt/" + p
    r = requests.get(url)
    ct = (json.loads(r.text))['ciphertext']
    return ct


def get_flag(pt):
    url = "http://aes.cryptohack.org/lazy_cbc/get_flag/" + pt
    r = requests.get(url)
    ct = r.text
    return ct


def decrypt(pt):
    url = "http://aes.cryptohack.org/lazy_cbc/receive/" + pt
    r = requests.get(url)
    plain = r.text
    return plain

#test methods
# ct = encrypt("0000000000000000".encode())
# print(ct)
# #{'ciphertext': '5ecf2b35217b6bfe5bde07f79635baee'}
#
# plain = decrypt("5ecf2b35217b6bfe5bde07f79635baee")
# print(plain)
# #{"success":"Your message has been received"}
#
# flag = get_flag("0000".encode())
# print(flag)
# # {"error":"invalid key"}

# okay, everything works fine
# there we again using the same key to cypher multiple batches

# during first block of decoding is using KEY as iv ()
# cipher = AES.new(KEY, AES.MODE_CBC, KEY)
# there is also no authorization check, so we can just modify decryption data
# by setting 2nd block to "0000000000000000" we can bypass cbc XOR operation on 3rd cycle
# So we have:
#   1. 1st decoded block w/ last XOR w/ encryption KEY
#   2. 3rd decoded block w/ no XOR operation at all
#  1st XOR 3rd = KEY (if decoding message is equal on both blocks)


ct = encrypt("123456789012345a123456789012345a123456789012345a".encode())
print(ct)
# ef5bd13ffe5575825dce055c7001b787ce76bf0b16bfb0b35479c3a66152634c21908046d655a4a673c10775adb78fc9

ct = encrypt("123456789012345a".encode())
print(ct)
#ef5bd13ffe5575825dce055c7001b787

plain = decrypt("ef5bd13ffe5575825dce055c7001b78700000000000000000000000000000000ef5bd13ffe5575825dce055c7001b787")
print(plain)
# {"error":"Invalid plaintext: 31323334353637383930313233343561473a67ab600982139aab1bef3fc1e589da342a18a5bc1e13e450d14e79aef8d7"}
# 31323334353637383930313233343561
# 473a67ab600982139aab1bef3fc1e589
# da342a18a5bc1e13e450d14e79aef8d7

# using tool on cryptohack website:
# 31323334353637383930313233343561 XOR da342a18a5bc1e13e450d14e79aef8d7 = eb06192c908a292bdd60e07c4a9acdb6

flag = get_flag("eb06192c908a292bdd60e07c4a9acdb6")
print(flag)
# {"plaintext":"63727970746f7b35306d335f703330706c335f64306e375f3768316e6b5f49565f31355f316d70307237346e375f3f7d"}

# 63727970746f7b35306d335f703330706c335f64306e375f3768316e6b5f49565f31355f316d70307237346e375f3f7d
# while entering a code i forgot that it is a HEX value

print(bytes.fromhex("63727970746f7b35306d335f703330706c335f64306e375f3768316e6b5f49565f31355f316d70307237346e375f3f7d").decode('utf-8'))
# crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}
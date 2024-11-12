from binascii import hexlify
import requests
import json
import codecs




def check_admin(cookie, iv):
    url = "http://aes.cryptohack.org/flipping_cookie/check_admin/"+cookie+"/"+iv+"/"
    r = requests.get(url)
    ct = r.text
    return ct

#test
# print(check_admin("aa", "bb"))


def get_cookie():
    url = "http://aes.cryptohack.org/flipping_cookie/get_cookie/"
    r = requests.get(url)
    cookie = (json.loads(r.text))['cookie']
    return cookie

#test
# print(get_cookie())


# let's take public iv first
print(get_cookie())
# bd45ee293c88862aecf81da625fad809df9b3951bb2ec093c229d0f03b5302c830a582fc7addbde4af63ffbfa83448be



# bd45ee293c88862aecf81da625fad809 - this it iv
# df9b3951bb2ec093c229d0f03b5302c8
# 30a582fc7addbde4af63ffbfa83448be - this is 'admin=False;expiry={expires_at}'


# in cypher
# some_cipher_hash (not actual key, but just simplifyed version of all operations) XOR message XOR IV
# we know message and iv

# “admin=False;expiry=” (hex: 61646d696e3d46616c73653b6578706972793d) XOR IV (bd45ee293c88862aecf81da625fad809) = dc21834052b5c04b808b789d4082a860
# this value is whatever algorithm decides to XOR w/ message for encryption

# now we can use it to calculate iv using which during decypherig we will get admin=True message
# “admin=True;expiry=” (61646d696e3d547275653b6578706972793d) XOR dc21834052b5c04b808b789d4082a860 = bd45ee293c889439f5ee43f838f2c112

print(check_admin("df9b3951bb2ec093c229d0f03b5302c830a582fc7addbde4af63ffbfa83448be", "bd45ee293c889439f5ee43f838f2c112"))
# {"flag":"crypto{4u7h3n71c4710n_15_3553n714l}"}
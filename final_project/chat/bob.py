import asyncio

from utils import bob_client, show, prompt, read_message_from_stdin
from algorithms_core import *


max_len = 1024
divider = "|||"
my_dhdr = None
nonce = 0

async def receive(reader):
    global max_len
    global divider
    global nonce

    """Receive data from other party"""
    while True:
        # Receive data from  (can be multiple messages)

        data = await reader.read(max_len)

        if not data:
            break

        data = data.decode()
        # print(data)
        data = data.split(divider)

        if len(data) != 4:
            break

        encrypted_message = data[0]
        pub_key_str = data[1]
        nonce_received = int(data[2])
        signature = data[3]

        if nonce_received != nonce + 1:
            break

        nonce = nonce_received

        # print(f"encrypted_message {encrypted_message}")
        # print(f"pub_key {pub_key_str}")
        # print(f"signature {signature}")

        pub_key = create_X22519PubKey_form_str(pub_key_str.encode())

        shared_key = my_dhdr.get_input_ratchet_key(pub_key)

        decrypted_message = AES_pkcs5(shared_key).decrypt(encrypted_message)

        if not validate_hmac_sha256(decrypted_message + pub_key_str + str(nonce_received), shared_key, signature):
            show("ERROR, signature not valid")
            break

        show(decrypted_message)

        prompt()

    show("ERROR, stopped listening")


async def send(writer):
    global divider
    global nonce
    """Send data to other party"""
    while True:

        message = await read_message_from_stdin()
        nonce = nonce + 1

        # {ENCRYPT HERE}
        shared_key = my_dhdr.get_output_ratchet_key()
        pub_key_to_send = my_dhdr.get_current_public_key_to_send()
        pub_key_str = pub_key_into_str(pub_key_to_send)

        message = message.strip()
        encrypted_message = AES_pkcs5(shared_key).encrypt(message)

        signature = sign_hmac_sha256(message + pub_key_str + str(nonce), shared_key)

        # Send message
        writer.write(f"{encrypted_message}{divider}{pub_key_str}{divider}{nonce}{divider}{signature}".encode())
        prompt()
        await writer.drain()



async def init_connection():
    reader, writer = await bob_client()
    print("Connected to Alice!")
    prompt()

    # INITIAL EXCHANGE HERE
    # initial DH key exchange
    init_pkey = generate_ec225519_private_key()
    init_pubkey = init_pkey.public_key()

    writer.write(pub_key_into_str(init_pubkey).encode()) # send my pub key
    received_pubkey_str = await reader.read(max_len) # receive pub key

    # deserialize PubKey
    received_pubkey = create_X22519PubKey_form_str(received_pubkey_str)

    # exchange constants for a I/O ratchet
    output_ratchet_const = uuid.uuid4().hex
    writer.write(output_ratchet_const.encode()) # send my output const
    input_ratchet_const = await reader.read(max_len) # receive input const
    input_ratchet_const = input_ratchet_const.decode()

    # init Diffie-Hellman Double Ratchet
    global my_dhdr
    my_dhdr = DiffieHellmanDoubleRatchet(init_pkey, received_pubkey, input_ratchet_const, output_ratchet_const)

    await asyncio.gather(receive(reader), send(writer))


if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())

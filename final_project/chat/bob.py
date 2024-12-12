import asyncio

from utils import bob_client, show, prompt, read_message_from_stdin
from algorithms_core import *


max_len = 1024
my_dhdr = None

async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Alice (can be multiple messages)
        global max_len

        data = await reader.read(max_len)
        print("1")
        print(f"{data.decode()}")
        pub_key = await reader.read(max_len)
        print("2")
        signature = await reader.read(max_len)
        print("3")
        if not data or not pub_key or not signature:
            break
        print("4")

        # pub_key = pub_key.decode()
        message = data.decode()
        signature = signature.decode()
        pub_key = create_X22519PubKey_form_str(pub_key)
        print("5")

        shared_key = my_dhdr.get_input_ratchet_key(pub_key)

        decrypted_message = AES_pkcs5(shared_key).decrypt(message)
        print("6")

        if not validate_hmac_sha256(decrypted_message+pub_key,shared_key, signature):
            show("ERROR, signature not valid")
            break
        print("7")

        show(decrypted_message)

        prompt()
    show("ERROR, stopped listening")


async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        shared_key = my_dhdr.get_output_ratchet_key()
        pub_key_to_send = my_dhdr.get_current_public_key_to_send()
        pub_key_str = pub_key_into_str(pub_key_to_send)

        message = message.strip()
        encrypted_message = AES_pkcs5(shared_key).encrypt(message)

        signature = sign_hmac_sha256(message + pub_key_str, shared_key)

        # Send message
        writer.write(encrypted_message.encode())
        writer.write(pub_key_str.encode())
        writer.write(signature.encode())
        await writer.drain()

        prompt()



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

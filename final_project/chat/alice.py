import asyncio

from utils import alice_server, prompt, show, read_message_from_stdin
from algorithms_core import *

max_len = 1024
shared_key = None


async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Bob (can be multiple messages)
        data = await reader.read(max_len)
        if not data:
            break

        message = data.decode()

        # {DECRYPT HERE}

        decrypted_message = AES_pkcs5(shared_key).decrypt(message)

        show(decrypted_message)

        prompt()


async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        encrypted_message = AES_pkcs5(shared_key).encrypt(message)

        data = encrypted_message.strip().encode()

        # Send message
        writer.write(data)

        prompt()
        await writer.drain()



async def init_connection(reader, writer):
    print("Connected with Bob!")
    prompt()

    init_pkey = generate_ec225519_private_key()
    init_pubkey = init_pkey.public_key()
    writer.write(pub_key_into_str(init_pubkey).encode())

    received_pubkey_str = await reader.read(max_len)

    received_pubkey = create_X22519PubKey_form_str(received_pubkey_str)

    global shared_key
    shared_key = finalize_ec_key(init_pkey, received_pubkey)


    # INITIAL EXCHANGE HERE

    await asyncio.gather(receive(reader), send(writer))


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))

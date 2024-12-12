# Cryptographic Algorithms

### Key Rotation:
● Diffie-Hellman Double Ratchet

### Key-agreement protocol
● ECDH w/ Curve25519

### Symmetric-key algorithm
● AES-CBC w/ addon PKCS #5
### Authentication (MAC)
● HMAC-SHA-256

### KDFs
● HMAC-SHA-256


# Motivation of choosing of algorithms:
I literally copied everything from signal protocol.
Also, I used HMAC for Key derivation **and** Auth because it can be used in both cases.
(1 algorithm make less code than 2 = less code make less amount of errors)

### Cryptographic qualities that is guaranteed: 
#### ● End-to-end security
is guaranteed by AES-CBC w/ addon PKCS #5
#### ● Forward security & Post-compromise security
is guaranteed by changing root keys w/ Elliptic Curve Diffie-Hellman protocol (Curve25519 is used) on every message in Diffie-Hellman Double Ratchet algorithm
#### ● Protection against interception by a man-in-the-middle
intercepting messages do not compromise keys because we used Diffie-Hellman protocol
#### ● Protection against man-in-the-middle attacks 
I used message authentication using HMAC-SHA-256 protocol
#### ● Protection against message replay attack
I'm keeping track of message number in case if somebody wants to re-send some messages. (message number / nonce is also authenticated)

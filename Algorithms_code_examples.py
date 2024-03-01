# Crypto library - Algorithms

"""cryptographic random number generator (CRNG)
Provide a code example that use secure random generate to generate a 256 bit (i.e. 32 bytes) value.
This value can be used as encryption key.
"""
# https://docs.python.org/3/library/secrets.html#module-secrets
# https://www.geeksforgeeks.org/convert-bytes-to-bits-in-python/
import secrets


def crng(nbytes):
    """Cryptographic random number generator

    Returns a random byte string containing nbytes number of bytes.
    """
    random_byte_str = secrets.token_bytes(nbytes)
    return random_byte_str


print(crng(32))


"""Shared-key (symmetric) cipher
Provide and example of using AES-256-GCM or AES-256-CBC to encrypt and decrypt a message.
That is AES (Advanced Encryption Standard) algorithm, with a key size of 256 bit and used in either Galois/counter (GCM) or CBC (Cipher block chaining) mode.
Your example should encrypt a message an decrypt it again.
Use previous code example to generate an encryption key.
You also need an IV (sometimes called Nonce). It is usually 96 bit long. Same IV is required for decryption.
You need to generate a new IV for each plain-text that you encrypt. Same IV shall not be used to encrypt multiple times with the same key.
"""
# Shared-key (symmetric) cipher - Example:
# https://onboardbase.com/blog/aes-encryption-decryption/
from Crypto.Cipher import AES


data = b'Something I want to encrypt.'
key = crng(32)
header = b"header"

# Encryption
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(header)

cipher_text, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce

# Decryption
decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypt_cipher.update(header)

plain_text = decrypt_cipher.decrypt_and_verify(cipher_text, tag)


"""Hashing
Provide an example that uses SHA512 to generate a hash of an input.
That is SHA-2 with an size of 512 bits.
"""
# https://debugpointer.com/python/create-sha512-hash-of-a-string-in-python
# UNUSED: https://debugpointer.com/python/create-sha512-hash-of-a-file-in-python
import hashlib


def sha512_hash_string(string_to_hash: str):
    str_to_bytes = string_to_hash.encode('UTF-8')
    hash_object = hashlib.sha512(str_to_bytes)
    hash_value = hash_object.hexdigest()
    return hash_value


sha512_hash_string('Text to hash!')


"""Message Authentication Code (MAC)
Provide an example that have a function to generate a hash-based message authentication (HMAC) using HMAC-SHA256 and a function to verify the HMAC.
You can generate a shared secret using the code from your first example.
"""
# https://browse-tutorials.com/snippet/python-generate-hmac-sha-256-string
# https://docs.python.org/3/library/hmac.html
# verify HMAC: https://gist.github.com/craigderington/9cb3ffaf4279af95bebcc0470212f788
import hmac


key = crng(32)
message = 'Body text for the hash.'

# Generate the hash.
hmac_digest = hmac.new(key, message.encode('UTF-8'), hashlib.sha256).hexdigest()


def verify_hmac(key, message, digest_to_verify):
    digest = hmac.new(key, message.encode('UTF-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest_to_verify, digest)


verify_hmac(key, message, hmac_digest)


"""Diffie-Hellman key exchange
Provide an example of using Curve25519 ECDH key exchange for two parties to compute the same shared secret.
That is elliptic-curve diffie-Hellman (ECDH) with Curve25519.
"""
# https://asecuritysite.com/keyexchange/python_25519ecdh
# https://pypi.org/project/x25519/
import binascii
from x25519 import scalar_base_mult, scalar_mult


a_private_key = crng(32)
b_private_key = crng(32)

print (f"\n\nBob private (b):\t{int.from_bytes(b_private_key)}")
print (f"Alice private (a): \t{int.from_bytes(a_private_key)}")

# Traditional ECDH:
a_public_key = scalar_base_mult(a_private_key)
b_public_key = scalar_base_mult(b_private_key)

print("\n\nBob public (bG):\t", binascii.hexlify(b_public_key))
print("Alice public (aG):\t", binascii.hexlify(a_public_key))

a_shared_secret_key = scalar_mult(a_private_key, b_public_key) # K = a (bG)
b_shared_secret_key = scalar_mult(b_private_key, a_public_key) # K = b (aG)

print("\n\nBob shared (b)aG:\t", binascii.hexlify(b_shared_secret_key))
print("Alice shared (a)bG:\t", binascii.hexlify(a_shared_secret_key))


"""Digital signatures
Provide an example of how to use Ed25519 to sign a message and verify its signature.
Ed25519 is short for EdDSA with Curve25519.
"""
# https://asecuritysite.com/encryption/nacl01
# https://pypi.org/project/PyNaCl/
import nacl.signing  # when installing the package name is PyNaCl
import binascii


msg = 'Message to send with digital signature'
message = msg.encode()

key_seed = crng(32)
private_key = nacl.signing.SigningKey(key_seed)

signed_message = private_key.sign(message)

public_key = private_key.verify_key

print("Message: ", message)
print("\nPrivate key: ", binascii.hexlify(private_key.encode()))
print("Public key: ", binascii.hexlify(public_key.encode()))
print("\nSignature (signed message): ", binascii.hexlify(signed_message))

# verify signature
rtn = public_key.verify(signed_message.message, signed_message.signature)

if rtn == message:
    print("\nSignature valid")
else:
    print("\nSignature invalid")


"""RSA (Rivest–Shamir–Adleman)
Provide an example of encrypting with RSA and decrypting.
"""
# https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


keyPair = RSA.generate(3072)
pubKey = keyPair.publickey()

# RSA Encryption
msg = b'A message for encryption'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted_message = encryptor.encrypt(msg)
print("Encrypted message:", binascii.hexlify(encrypted_message))

# RSA Decryption
decryptor = PKCS1_OAEP.new(keyPair)
decrypted_message = decryptor.decrypt(encrypted_message)
print('Decrypted message:', decrypted_message)


"""Key derivation
Provide an example of using PBKDF2-HMAC-SHA512 to derive a key from a password.
That is PBKDF2 (Password-Based Key Derivation Function 2) using HMAC-SHA512 as the underlaying algorithm.
"""
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html
# you can either specify salt or salt length: https://stackoverflow.com/questions/39647123/salt-in-pbkdf2-python
from passlib.hash import pbkdf2_sha512


password = "Produce a derived key from this password. You this derived key for subsequent operations - key stretching."
rounds = 8000
salt_size_bytes = 32

# generate new salt, hash password
hashed_password = pbkdf2_sha512.using(rounds=rounds, salt_size=salt_size_bytes).hash(password)
#hashed_password = pbkdf2_sha512.using(rounds=rounds, salt=b"SomeSaltValue").hash(password)  # alternatively specifying salt

# verify the password
pbkdf2_sha512.verify(password, hashed_password)

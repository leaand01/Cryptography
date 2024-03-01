"""Aflevering del 2
Write a program that uses hybrid cryptography to send messages.
Use asymmetric cryptography in combination with key exchange to share a session key. Then use symmetric cryptography to
an exchange message using the session key.
I recommend Elliptic-curve Diffie–Hellman (ECDH) for key exchange and AES-GCM-256 for messages.

Exchange public keys
On both ends, derive a key from the original key pair and the partners public key
One side generates a session key, encrypts it with derived key
Partner decrypts the session key using derived key
Use session key to encrypt+decrypt message
"""
import binascii
import ecdh
import aes_gcm


print('\n\nPerson A wants to send an encrypted message to Person B.')
print('A and B shares a secure connection across an insecure channel by using ECDH.')
print('Person A encrypts a message using AES-GCM-256 encryption.')


a_public, a_private = ecdh.generate_key_pair(32)
b_public, b_private = ecdh.generate_key_pair(32)
print('\nGenerating key pair of person A and B.')
print("A public key:  ", binascii.hexlify(a_public))
print("A private key: ", binascii.hexlify(a_private))
print("B public key:  ", binascii.hexlify(b_public))
print("B private key: ", binascii.hexlify(b_private))


a_shared = ecdh.generate_shared_key(a_private, b_public)
b_shared = ecdh.generate_shared_key(b_private, a_public)
print('\nGenerating a shared secret key for person A and B.')
print("Person A's shared_key: ", binascii.hexlify(a_shared))
print("Person B's shared_key: ", binascii.hexlify(b_shared))
print("identical shared key: ", a_shared == b_shared)


a_message = 'This is a secret message...sssshh!'
cipher_text, tag, nonce = aes_gcm.encrypt_message(a_message, a_shared)
print('\nPerson A encrypts message.')
print("A's message: ", a_message)
print("Encrypted message: ", binascii.hexlify(cipher_text))


b_message = aes_gcm.decrypt_message(cipher_text, tag, nonce, b_shared)
print('\nPerson B decrypts the message.')
print('Decrypted message: ', b_message)

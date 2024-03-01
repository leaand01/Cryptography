from Crypto.Cipher import AES


def encrypt_message(msg_string: str, shared_secret_key: bytes) -> (bytes, bytes, bytes):
    """AES-GCM-xxx encryption, where
    xxx is 256 if shared_secret_key is of 256 bits, i.e. 32 bytes.
    """
    msg_bytes = msg_string.encode('UTF-8')
    header = b'header'

    # Encryption
    cipher = AES.new(shared_secret_key, AES.MODE_GCM)
    cipher.update(header)

    cipher_text, tag = cipher.encrypt_and_digest(msg_bytes)
    nonce = cipher.nonce

    return cipher_text, tag, nonce


def decrypt_message(cipher_text: bytes, cipher_tag: bytes, cipher_nonce: bytes, shared_secret_key: bytes) -> str:
    header = b'header'

    # Decryption
    decrypt_cipher = AES.new(shared_secret_key, AES.MODE_GCM, nonce=cipher_nonce)
    decrypt_cipher.update(header)

    plain_text_bytes = decrypt_cipher.decrypt_and_verify(cipher_text, cipher_tag)
    return plain_text_bytes.decode('UTF-8')

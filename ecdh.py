import secrets
from x25519 import scalar_base_mult, scalar_mult


def crng(nbytes: int = 32) -> bytes:
    """Cryptographic random number generator

    Returns a random byte string containing nbytes number of bytes.
    """
    random_byte_str = secrets.token_bytes(nbytes)
    return random_byte_str


def generate_key_pair(nbytes: int = 32) -> (bytes, bytes):
    """Generates a public-private key pair using the Elliptic-curve Diffie-Hellman (ECDH) procedure.
    The key pair is used to establish a shared secret key to use over an insecure channel.
    Per default, it generates a keys of length 256 bits.
    """
    private_key = crng(nbytes)
    public_key = scalar_base_mult(private_key)
    return public_key, private_key


def generate_shared_key(private_key: bytes, public_key: bytes) -> bytes:
    """Generates a shared secret key between two parties (person a and b) by using their public-private ECDH key pair.
    Note, if the private key is person a's then the public key must be person b's and vice versa.
    The shared secret key must be identical for person a and b.
    """
    shared_secret_key = scalar_mult(private_key, public_key)
    return shared_secret_key


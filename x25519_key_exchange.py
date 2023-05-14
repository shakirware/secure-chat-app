from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_encryption_key(private_key, peer_public_key, salt=None, info=None, length=32):
    shared_secret = private_key.exchange(peer_public_key)
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=backend
    )
    return hkdf.derive(shared_secret)
    
    
    
"""
key_exchange = X25519KeyExchange()

# Party A generates a key pair
private_key_a, public_key_a = key_exchange.generate_key_pair()

# Party B generates a key pair
private_key_b, public_key_b = key_exchange.generate_key_pair()

# Party A derives the shared secret
shared_secret_a = private_key_a.exchange(public_key_b)

# Party B derives the shared secret
shared_secret_b = private_key_b.exchange(public_key_a)

# Both parties derive the encryption key
encryption_key_a = key_exchange.derive_encryption_key(private_key_a, public_key_b)
encryption_key_b = key_exchange.derive_encryption_key(private_key_b, public_key_a)"""
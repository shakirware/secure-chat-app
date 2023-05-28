from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

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
    
    
   
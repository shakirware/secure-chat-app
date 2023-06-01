from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

participants = {
    "Alice": x25519.X25519PrivateKey.generate(),
    "Bob": x25519.X25519PrivateKey.generate(),
    "Charlie": x25519.X25519PrivateKey.generate()
}



group_private_key = x25519.X25519PrivateKey.generate()
group_public_key = group_private_key.public_key()
serialized_group_public_key = group_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

# Get shared secrets for each participant
shared_secrets = {}
for participant, private_key in participants.items():
    shared_secrets[participant] = private_key.exchange(group_public_key)
    
print(shared_secrets)
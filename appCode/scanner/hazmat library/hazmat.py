from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import binascii as ba


bob_private_key = X25519PrivateKey.generate()
print(bob_private_key)

bob_private_bytes = bob_private_key.private_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PrivateFormat.Raw, 
     encryption_algorithm=serialization.NoEncryption()
)

#print(bob_private_bytes)

alice_private_raw = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
alice_public_raw = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
bob_private_raw = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
bob_public_raw = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'

alice_private_hex_bytes = alice_private_raw.encode('utf-8')
alice_private_hex_bytes = ba.unhexlify(alice_private_hex_bytes)

bob_public_hex_bytes = bob_public_raw.encode('utf-8')
bob_public_hex_bytes = ba.unhexlify(bob_public_hex_bytes)

alice_private_key = x25519.X25519PrivateKey.from_private_bytes(alice_private_hex_bytes)
print("\nAlice private key")
print(alice_private_key)

bob_public_key = X25519PublicKey.from_public_bytes(bob_public_hex_bytes)
print("\nBob public key")
print(bob_public_key)

shared_key = alice_private_key.exchange(bob_public_key)
print("\nShared key")
print(shared_key)
print(ba.hexlify(shared_key))

# print("\Bob private key")
# print(bob_private_key)

# alice_public_key = X25519PublicKey.from_public_bytes(alice_public_hex_bytes)
# print("\Alice public key")
# print(alice_public_key)
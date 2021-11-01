from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import binascii as ba

'''
Program to generate public and priate key for permanent use on server
To be used for HMAC or encrypting dongle advert data with public key.

'''

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

print(ba.hexlify(private_key_bytes))

public_key_btes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

print(ba.hexlify(public_key_btes))
import binascii as ba
from nacl import public
import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box, PublicKey

private_key = PrivateKey.generate()
public_key = private_key.public_key


#print(private_key.encode(encoder=nacl.encoding.HexEncoder))
#print(public_key.encode(encoder=nacl.encoding.HexEncoder))
#print(private_key.encode(encoder=nacl.encoding.HexEncoder).len())

#print("Public_key:")
#print(public_key)
print("public key original")
print(public_key)

print("\npublic key encoded to hex")
a = public_key.encode(encoder=nacl.encoding.HexEncoder)
print(a)

# b = a.decode('utf-8')
# print(a)
# print(b)
print("\npublic key to string")
pub_str = a.decode("utf-8")
print(pub_str)

print("\npublic key utf back to hex")
pub_hex = pub_str.encode('utf-8')
print(pub_hex)
pub_hex = ba.unhexlify(pub_hex)
print(pub_hex)

print("\nback to original")
pub_origin = PublicKey(pub_hex)
print(pub_origin)

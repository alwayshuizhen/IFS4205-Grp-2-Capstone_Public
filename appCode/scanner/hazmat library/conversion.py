import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box, PublicKey
import binascii as ba


alice_private_raw = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
alice_public_raw = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

alice_private_hex = ba.unhexlify(alice_private_raw)
print(alice_private_hex)


'''
a = "TEST".encode('utf-8')
b = ba.hexlify(a)
print(b)

c = ba.unhexlify(b)
print(c)
'''
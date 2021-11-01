import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box, PublicKey
import binascii as ba



# alice_private_raw = '74217655549757017210819731522004692777666482923065579825632492030562645183555'
# alice_public_raw = '11388CC1AACACC9B781DD9019C82B021D04F8B6742EF6B8E01E1B845DC82295B'

# bob_private_raw = '9499f3f90ad9b479083cdaa7ca54214aaee4c7b2078a0a849775adbb4a08f6c6'
# bob_public_raw = 'aea45acff6019229eea97be208a6909301c828d60364c7aabe75c094b697ee3f'


alice_private_raw = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
alice_public_raw = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

bob_private_raw = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
bob_public_raw = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'


# alice_private_raw = '70076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C6A'
# alice_public_raw = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

# bob_private_raw = '58AB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E06B'
# bob_public_raw = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'

print(ba.unhexlify(alice_private_raw.encode('utf-8')))

alice_private = alice_private_raw.encode('utf-8')
alice_private = ba.unhexlify(alice_private)
alice_private = PrivateKey(alice_private)

alice_public = alice_public_raw.encode('utf-8')
alice_public = ba.unhexlify(alice_public)
alice_public = PublicKey(alice_public)

bob_private = bob_private_raw.encode('utf-8')
bob_private = ba.unhexlify(bob_private)
bob_private = PrivateKey(bob_private)

bob_public = bob_public_raw.encode('utf-8')
bob_public = ba.unhexlify(bob_public)
bob_public = PublicKey(bob_public)

box = Box(bob_private, alice_public)
shared_secret = box.shared_key()
print("On scanner side: ")
print(ba.hexlify(shared_secret))

box = Box(alice_private, bob_public)
shared_secret = box.shared_key()
print("\nOn dongle side: ")
print(ba.hexlify(shared_secret))
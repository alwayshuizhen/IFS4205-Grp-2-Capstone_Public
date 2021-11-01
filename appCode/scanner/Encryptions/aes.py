import os
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii as ba
import sys
import secrets

'''
Sample program to test AES encryption and whether it matches with dongle library

'''

#key = ba.unhexlify("2B7E151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4F3C".encode('utf-8'))
iv = ba.unhexlify("4ef4ebbdd28e8cd358130150aedff903".encode('utf-8'))
#ct = ba.unhexlify("E738239C4A27FB76A7F1645781AE7CB00C2B7BD231B0D0BAAE61E434FC08415846CB1CAC7CE404BB744455806A747FF6B2400F5B5479575233BCD0E2BEDADE97".encode('utf-8'))

ct = ba.unhexlify("43FACC53C48799511C78DD88A8786935D68526AFE9199C3821C39CA32C95AC8F7D804085450040A52C8F6F3D69A15CBF832868292671894711EC7234536EE347".encode('utf-8'))
key = ba.unhexlify("21960293BE8E47951BA8D24D03B8D3E79B5EE470BC07E643DFAA5A131818E937".encode('utf-8'))
# key = "2B7E151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4F3C".encode('utf-8')
# iv = "000102030405060708090A0B0C0D0E0F".encode('utf-8')
#ct = "E738239C4A27FB76A7F1645781AE7CB00C2B7BD231B0D0BAAE61E434FC08415846CB1CAC7CE404BB744455806A747FF6B2400F5B5479575233BCD0E2BEDADE97".encode('utf-8')

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
message = decryptor.update(ct) + decryptor.finalize()
a = ba.hexlify(message).decode('utf-8')
print(ba.hexlify(message).decode('utf-8'))
a = a.split('2e')
print(ba.unhexlify(a[0]).decode())
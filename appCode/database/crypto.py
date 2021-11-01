from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import os
import base64
import hashlib

def encrypt(plainText, password):
    salt = os.urandom(AES.block_size)
    iv = get_random_bytes(AES.block_size)
    privateKey = hashlib.scrypt(password.encode(), salt = salt, n = 2 ** 14, r = 8, p = 1, dklen = 32)
    configureCipher = AES.new(privateKey, AES.MODE_CBC, iv)
    cipherText = base64.b64encode(configureCipher.encrypt(pad(plainText.encode('utf-8'), 16)))
    salt = base64.b64encode(salt)
    iv = base64.b64encode(iv)
    password = base64.b64encode(password.encode('utf-8'))
    encryptedInfo = cipherText + b":" + salt + b":" + iv + b":" + password
    return encryptedInfo.decode('utf-8')

def decrypt(encryptedInfo):
    sliced = encryptedInfo.split(":")
    cipherText = base64.b64decode(sliced[0])
    salt = base64.b64decode(sliced[1])
    iv = base64.b64decode(sliced[2])
    password = base64.b64decode(sliced[3])
    privateKey = hashlib.scrypt(password, salt = salt, n = 2 ** 14, r = 8, p = 1, dklen = 32)
    configureCipher = AES.new(privateKey, AES.MODE_CBC, iv)
    decryptedInfo = unpad(configureCipher.decrypt(cipherText), 16)
    return decryptedInfo.decode('utf-8')

password = os.urandom(12).hex()

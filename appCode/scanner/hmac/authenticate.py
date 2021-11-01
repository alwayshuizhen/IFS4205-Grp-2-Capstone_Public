

import hmac
import hashlib
import binascii as ba

def create_sha256_signature(key, message):
    byte_key = key
    #print(byte_key)
    #print(key)
    message = message.encode()
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()

# key = "3ECD31B7301C51C8664DE9B298E33B87292DBB50F710420726802502AEAB0207"
key = "96D3F04834BEA592AB2AA09FE4757702158CCDCC384AE82A857B2F3AF0B6F259"
#key = ba.hexlify(key.encode('utf-8'))
key = key.encode()
message = "D63046BFB100353483860EAA35D6E6275C495E844DFB57DA2F73C46132025F8F666F4C1579F7A4465FC4D3FDF086855C73E5DB0B5128667ECAF98F7E11C24F0C"
#print(key)
a = create_sha256_signature(key, message)

print(a)
from cryptography.hazmat.primitives import ciphers, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import Advertisement, ProvideServicesAdvertisement
from adafruit_ble.services.standard.device_info import DeviceInfoService
from adafruit_ble.services import Service
from adafruit_ble.services.gmsservice import GMS

import binascii as ba
import secrets
import time
'''
Main program to communicate with dongle

'''
# generate 16 byte
def generate_iv():
    iv = secrets.token_hex(16)
    return iv.encode('utf-8')


# function to receive form dongle - not working 
# receive first half, send reply, receive second half

def receive_aes(GMS_service):
    receiving = False
    while not receiving:
        data_from_dongle = GMS_service.readline().decode("utf-8")
        if (data_from_dongle):
            receiving = True
    GMS_service.write("received")
    return data_from_dongle



# takes in a working GMS connection and does the DH exchange for shared key
def dh_exchange(GMS_service):

    # setting up of new keys per new dongle connection
    scanner_private_key = X25519PrivateKey.generate()
    scanner_public_key = scanner_private_key.public_key()

    # sending public key over
    scanner_public_key_bytes = scanner_public_key.public_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PublicFormat.Raw, 
    )
    scanner_public_key_bytes_hex = ba.hexlify(scanner_public_key_bytes)
    scanner_public_key_bytes_hex_str = scanner_public_key_bytes_hex.decode('utf-8')
    
    print("Scanner:\tSending public key --> \n" + str(scanner_public_key_bytes_hex_str))
    GMS_service.write(scanner_public_key_bytes_hex)

    # receiving dongle public key
    receiving = False
    while not receiving:
        dongle_public_key_bytes_hex_str = GMS_service.readline().decode("utf-8")
        #print (dongle_public_key)
        if (dongle_public_key_bytes_hex_str):
            receiving = True
        
    
    # continue to process and send back secret if dongle public key is 64 bytes
    if (len(dongle_public_key_bytes_hex_str) == 64):
        print("Dongle:\t\tReceive public key --> \n" + dongle_public_key_bytes_hex_str)

        # convert string dongle key to public key format
        dongle_public_key_bytes_hex = dongle_public_key_bytes_hex_str.encode("utf-8")
        dongle_public_key_bytes = ba.unhexlify(dongle_public_key_bytes_hex)
        dongle_public_key =  X25519PublicKey.from_public_bytes(dongle_public_key_bytes)
       
        shared_key = scanner_private_key.exchange(dongle_public_key)
        print("Scanner:\tShared Secret -->")
        print(ba.hexlify(shared_key))
        
        # send IV and prepare for decrpytion of dongle data
        iv_hex = generate_iv()
        print("Scanner:\tSending IV --> \n" + str(iv_hex))
        GMS_service.write(iv_hex)

        # receiving 128 hex byte cipher text over two messages
        ciphertext_first_half = GMS_service.readline().decode("utf-8")
        print("Scanner:\tSending confirmation of first half ")
        GMS_service.write("6".encode('utf-8'))
        ciphertext_second_half = GMS_service.readline().decode("utf-8")
        ciphertext = ciphertext_first_half + ciphertext_second_half
        print("Dongle:\t\tReceive ciphertext --> \n" + ciphertext)

        # prepare for decryption 
        iv = ba.unhexlify(iv_hex)
        ct = ba.unhexlify(ciphertext.encode('utf-8'))

        if (len(ciphertext) == 128):

            cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            message_bytes = decryptor.update(ct) + decryptor.finalize()

            message_bytes_hex = ba.hexlify(message_bytes).decode('utf-8')
            message_bytes_hex_split = message_bytes_hex.split('2e')
            dongle_name = ba.unhexlify(message_bytes_hex_split[0]).decode('utf-8')
            dongle_phone = ba.unhexlify(message_bytes_hex_split[1]).decode('utf-8')
            print("Scanner:\tName: " + dongle_name + ", Phone: " + dongle_phone)

        
    else:
        print("Failure:\tReceived " + str(len(dongle_public_key_bytes_hex_str)) + "/ 64 byes of DH public key")
        return False

def main():
    ble = BLERadio()
    GMS_connection = None
    dongle_id = "IFS4205"

    while True:
        if not GMS_connection:
            print("Scanner:\tTrying to connect")
            
            # checking though all available services and picking out GMS
            for adv in ble.start_scan(ProvideServicesAdvertisement, timeout=2):
                name = adv.complete_name
                if not name:
                    continue
                if name == dongle_id:
                    if GMS in adv.services:
                        try:
                            # Attemping to decrypt and verify name
                            #print("Scanner:\t Verifying connection...")

                            print("Scanner:\tEstablishing connection...")
                            
                            GMS_connection = ble.connect(adv)
    
                            

                        except ConnectionError:
                            try:
                                GMS_connection.disconnect()
                                print("Dongle:\t\t Connection Error")
                            except ConnectionError:
                                GMS_connection = None
                
        

            # Establish r/w over GMS 
            if GMS_connection and GMS_connection.connected:
                GMS_service = GMS_connection[GMS]
                #dh_setup()
                dh_exchange(GMS_service)

            else :
                GMS_connection = None
                print("Scanner:\tNo connection, terminating")
            
            '''
            1. Send over scanner public key
            2. Receive public key from dongle 
            3. 
            '''
            break
        break

            # reset GMS_connection once too far or transaction complete

if __name__ == "__main__":
    main()
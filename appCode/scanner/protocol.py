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
import secrets, random, string


import hmac
import hashlib

FAIL = 13 # checksum len failure index
CHECKSUM_PACKET_LENGTH = 20
WEIGHTS = [0, 3, 2, 7, 6, 1, 1]
REMAINDER = ['Y','X', 'W', 'U', 'R', 'N', 'M', 'L', 'J', 'H', 'E', 'A', 'B', 'O']
    

def create_sha256_signature(key, message):
    message = message.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest().upper()

# message shoud be the ciphertext
def authenticate_dongle_data(key, message, GMS_service):
    # send signal to transmit HMAC
    if (not GMS_service):
        return False
    GMS_service.write("8".encode('utf-8'))

    key = ba.hexlify(key).decode('utf-8').upper()
    scanner_hmac = create_sha256_signature(key.encode(), message)

    receiving = False
    while not receiving:
        dongle_hmac = GMS_service.readline().decode("utf-8")
        if (dongle_hmac):
            receiving = True

    if len(dongle_hmac) != 64:
        return False

    else: 
        print("Dongle:\t\tDongle HMAC -->")
        print(dongle_hmac) 
        print("Scanner:\tScanner HMAC -->")
        print(scanner_hmac)

        if dongle_hmac != scanner_hmac:
            print("Scanner:\tDongle HMAC does ot match Scanner HMAC")
            return False
        else:
            print("Scanner:\tHMAC is valid")
            return True



def get_letter(input):
    if len(input) != 7:
        return REMAINDER[FAIL]
    else:
        print("Dongle:\t\tChecksum String: " + str(input))
        sum = 0
        for i in range(7):
            sum = sum + (int(input[i]) * int(WEIGHTS[i]))

        return (REMAINDER[sum%13],sum%13)

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

# prepre checksum packet for sending, make it within 20 bytes. 
# remainder value will be position of letter

def checksum_exchange(GMS_service, checksum_checker):
    checksum_letter = checksum_checker[0]
    checksum_index = int(checksum_checker[1])
    print("Scanner:\tSending checksum --> ")
    checksum_packet_padd = ''.join(random.choices(string.ascii_letters + string.digits, k=CHECKSUM_PACKET_LENGTH))
    checksum_packet = checksum_packet_padd[:checksum_index] + checksum_letter + checksum_packet_padd[ checksum_index + 1 :]
    print(checksum_packet)
    GMS_service.write(checksum_packet.encode('utf-8'))


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
        GMS_service.write("7".encode('utf-8'))
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
            
            # is_data_authenticated = authenticate_dongle_data(shared_key, message_bytes_hex, GMS_service)
            is_data_authenticated = authenticate_dongle_data(shared_key, ciphertext, GMS_service)

            if (is_data_authenticated):

                message_bytes_hex_split = message_bytes_hex.split('2e')
                dongle_name = ba.unhexlify(message_bytes_hex_split[0]).decode('utf-8')
                dongle_phone = ba.unhexlify(message_bytes_hex_split[1]).decode('utf-8')
                dongle_id = ba.unhexlify(message_bytes_hex_split[2]).decode('utf-8')
                print("Scanner:\tName: " + dongle_name + ", Phone: " + dongle_phone + ", Dongle ID: " + dongle_id)
                return (dongle_name, dongle_phone, dongle_id)

            else:
                return False
    else:
        print("Failure:\tReceived " + str(len(dongle_public_key_bytes_hex_str)) + "/ 64 byes of DH public key")
        return False

def get_dongle_data():
    """
    Connects with dongle and returns stored data

    :return dongle_data a tuple consisting of 1.name 2.phone 3.dongle_id
    """

    ble = BLERadio()
    GMS_connection = None
    #dongle_id = "IFS4205"

    while True:
        if not GMS_connection:
            print("Scanner:\tTrying to connect")
            
            # checking though all available services and picking out GMS
            
            for adv in ble.start_scan(ProvideServicesAdvertisement, timeout=2):
                name = adv.complete_name
                if not name:
                    continue
                
                try:
                    print("Scanner:\tVerifying checksum...")
                    checksum_checker = get_letter(name)
                    print("Scanner:\tChecksum: " + checksum_checker[0] + ", Position: " + str(checksum_checker[1]))
                
                    if checksum_checker[0] != "O": # O signifies failed checksum length

                        if GMS in adv.services:
                            try:
                                # Attemping to decrypt and verify name
                                print("Scanner:\tEstablishing connection...")                        
                                GMS_connection = ble.connect(adv)

                            except ConnectionError:
                                try:
                                    GMS_connection.disconnect()
                                    print("Dongle:\t\t Connection Error")
                                except ConnectionError:
                                    GMS_connection = None
                except:
                    print("Scanner:\tChecksum transmission error")
                    break

                    
               
            # Establish r/w over GMS 
            if GMS_connection and GMS_connection.connected:
                GMS_service = GMS_connection[GMS]
                checksum_exchange(GMS_service,checksum_checker)
                #dh_setup()
                dongle_data = dh_exchange(GMS_service)
                if(dongle_data):
                    GMS_connection.disconnect()
                    GMS_connection = None
                    return dongle_data
            else :
                GMS_connection = None
                print("Scanner:\tNo connection, terminating")
                return False
            '''
            1. Send over scanner public key
            2. Receive public key from dongle 
            3. 
            '''
            break
        break

            # reset GMS_connection once too far or transaction complete


from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import Advertisement, ProvideServicesAdvertisement
from adafruit_ble.services.standard.device_info import DeviceInfoService
from adafruit_ble.services import Service
import binascii as ba
from adafruit_ble.services.gmsservice import GMS

import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box, PublicKey



# takes in a working GMS connection and does the DH exchange for shared key
def dh_exchange(GMS_service):

    # setting up of new keys per new dongle connection
    scanner_private_key = PrivateKey.generate()
    scanner_public_key = scanner_private_key.public_key

    # sending public key over
    hex_scanner_public_key = scanner_public_key.encode(encoder=nacl.encoding.HexEncoder)
    
    hex_scanner_private_key = scanner_private_key.encode(encoder=nacl.encoding.HexEncoder)
    print("Scanner:\ private key --> \n" + str(hex_scanner_private_key))


    print("Scanner:\tSending public key --> \n" + str(hex_scanner_public_key))
    #print(hex_scanner_public_key)
    GMS_service.write(hex_scanner_public_key)

    # receiving dongle public key
    receiving = False
 
    while not receiving:
        dongle_public_key_str = GMS_service.readline().decode("utf-8")
        #print (dongle_public_key)
        if (dongle_public_key_str):
            receiving = True
        
    
    # continue to process and send back secret if dongle public key is 64 bytes
    if (len(dongle_public_key_str) == 64):
        print("Dongle:\t\tReceive public key --> \n" + dongle_public_key_str)

        # convert string dongle key to public key format
        dongle_public_key_bytes = dongle_public_key_str.encode("utf-8")
        dongle_public_key_hex = ba.unhexlify(dongle_public_key_bytes)
        dongle_public_key =  PublicKey(dongle_public_key_hex)
       
        box = Box(scanner_private_key, dongle_public_key)
        shared_secret = box.shared_key()
        print(shared_secret)
        print("Scanner:\tShared Secret -->\n")
        print(ba.hexlify(shared_secret))
        
        #print(shared_secret)
        
    else:
        print("Failure:\t\t Received " + str(len(dongle_public_key_str)) + "/ 64 byes of DH public key")
        return False

def main():
    ble = BLERadio()
    GMS_connection = None

    while True:
        if not GMS_connection:
            print("Scanner:\tTrying to connect")
            
            # checking though all available services and picking out GMS
            for adv in ble.start_scan(ProvideServicesAdvertisement):
                if GMS in adv.services:
                    try:
                        # Attemping to decrypt and verify name
                        #print("Scanner:\t Verifying connection...")

                        print("Scanner:\tEstablishing connection...")
                        GMS_connection = ble.connect(adv)
                        break

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
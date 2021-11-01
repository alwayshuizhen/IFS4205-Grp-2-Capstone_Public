from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import Advertisement, ProvideServicesAdvertisement
from adafruit_ble.services.standard.device_info import DeviceInfoService
from adafruit_ble.services import Service
import binascii as ba
from adafruit_ble.services.gmsservice import GMS

import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box



# takes in a working GMS connection and does the DH exchange for shared key
def dh_exchange(GMS_service):

    # setting up of new keys per new dongle connection
    scaner_private_key = PrivateKey.generate()
    scanner_public_key = scaner_private_key.public_key

    # sending public key over
    hex_scanner_public_key = scanner_public_key.encode(encoder=nacl.encoding.HexEncoder)
    print("Scanner:\tSending public key --> " + str(hex_scanner_public_key))
    print(hex_scanner_public_key)
    GMS_service.write(hex_scanner_public_key)

    # receiving dongle public key
    receiving = False
 
    while not receiving:
        dongle_public_key = GMS_service.readline().decode("utf-8")
        print (dongle_public_key)
        if (dongle_public_key):
            receiving = True
        
    print("Dongle:\t\tReceive public key --> " + dongle_public_key)


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
                            print("Dongle:\t\t Disconnected")
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
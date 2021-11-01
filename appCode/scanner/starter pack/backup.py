from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import Advertisement, ProvideServicesAdvertisement
from adafruit_ble.services.standard.device_info import DeviceInfoService
from adafruit_ble.services import Service
import adafruit_ble as ble
import binascii as ba
from adafruit_ble.services.gmsservice import GMS

radio = BLERadio()
dongle_id = "IFS4205"
dongle_connection = None


while True:
    print("Scanner:\tScanning...")

    for adv in radio.start_scan(Advertisement, timeout=10):
        name = adv.complete_name
        if not name:
            continue
        if name == dongle_id:
            dongle_connection = radio.connect(adv)
            print("Dongle:\t\tConnected to ->" + adv.complete_name)
            break
    
    radio.stop_scan()
    print("Scanner:\tStopped scan")

    try:
        # Try to fetch dongle device information, might use to determind mac of device
        if dongle_connection and dongle_connection.connected:
            print("Dongle:\t\tFetch connection...")
            if DeviceInfoService in dongle_connection:
                print("Dongle:\t\tDevice info:")
                print(DeviceInfoService)
            else:
                print("Dongle:\t\tNo device information")
        
        # Fetch transmitted data
        
            #print("YAY!")
    except ConnectionError:
        try:
            dongle_connection.disconnect()
            print("Dongle:\t Disconnected")
        except ConnectionError:
            pass
        dongle_connection = None

       
'''
# Experimental UART service

uart = UARTService()
uart_connection = None

while True:
    if not uart_connection:
        print("Trying to connect...")
        for adv in radio.start_scan(ProvideServicesAdvertisement):
            if UARTService in adv.services:
                uart_connection = radio.connect(adv)
                print("Connected")
                break
'''

print("Scan Complete.")

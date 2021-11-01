from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import Advertisement
from adafruit_ble.services.standard.device_info import DeviceInfoService
import adafruit_ble as ab
import binascii as ba

radio = BLERadio()
print("Scanning...")
found = set()

for entry in radio.start_scan(timeout=20, minimum_rssi=-80):
    addr = entry.address
    if addr not in found:
        print("======= New device ========")
        print("   ", end = '')
        print(entry.complete_name)
        print("      ", end = '')
        print(entry.address)
        print("      ", end = '')
        print(repr(entry))

        print("\nTry:")
        print(entry)
        item = repr(entry)[21:-2]
        #print(ab.advertising.decode_data(entry))
        print("\nOriginal")
        print(item)

        print("\nAfter:")
        item2 = item.encode()
        print(item2)

        print("\nTo ASCII:")
        print(item.encode('raw_unicode_escape').decode('unicode_escape')
)
        break


    found.add(addr)

print("Scan Complete.")

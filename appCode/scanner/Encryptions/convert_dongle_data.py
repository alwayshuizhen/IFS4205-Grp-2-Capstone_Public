import binascii as ba
import secrets

'''
Program is used to prepare data for hard coding into dongle
* Pads name and phone number to a size of 64 bytes, period delineated 
* format: name.number.dongle_id.padd
'''

MAX_SIZE = 128

name = "Daisy the Flower"
number = "55555555"
dongle_id = "5"

dongle_data = name + "." + number + "." + dongle_id + "."
dongle_data = ba.hexlify(dongle_data.encode('utf-8'))
print(dongle_data)
remaining_pad_size = MAX_SIZE - len(dongle_data)
#print(remaining_pad_size)
remaining_pad = secrets.token_hex(int(remaining_pad_size/2)).encode('utf-8') #remaining pad / 2 for number of bytes in one hex
print(remaining_pad)
complete_data = dongle_data + remaining_pad
if len(complete_data) == MAX_SIZE:
    # print("Final length = " + str(len(complete_data)))
    # print(complete_data)
    # print(ba.unhexlify(complete_data)) # needed for scanner side to decode

    #convert it to uint8 format for dongle
    complete_data_str = complete_data.decode('utf-8')
    convert_data = ['0x'+complete_data_str[i:i+2] for i in range(0, MAX_SIZE, 2)]
    convert_data = ','.join(convert_data)
    print(convert_data)
    #print(ba.unhexlify(complete_data))
else:
    print(ba.unhexlify(complete_data))
    print("Error: Length is not " + str(MAX_SIZE) + " is " + str(len(complete_data)))


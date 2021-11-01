import protocol as p

# to get dongle information, receives tuple 1. name 2. phone 3. dongle ID
dongle_data = p.get_dongle_data()
print("from test:")
print(dongle_data)
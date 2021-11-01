
'''
weights - 7 digits
w1 w2 w3 w4 w5 w6 w7
0  3  2  7  6  1  1

Remainder - mod 13
0 1 2 3 4 5 6 7 8 9 10 11 12 fail
Y X W U R N M L J H E  A  B  O

Dongle will check the n-th letter to see if it is the correct letter

'''


import binascii as ba
import secrets

FAIL = 14

weights = [0, 3, 2, 7, 6, 1, 1]
remainder = ['Y','X', 'W', 'U', 'R', 'N', 'M', 'L', 'J', 'H', 'E', 'A', 'B', 'O']

def get_letter(input):
    if len(input) != 7:
        return remainder[FAIL]
    else:
        sum = 0
        for i in range(7):
            sum = sum + (int(input[i]) * int(weights[i]))

        return remainder[sum%13]


input = "1234567"
print(get_letter(input))
"""
    My implementation of rijndael aes, written for Cryptography (Fall 2021)

    This program will be able to take an input from the user via command line, and provide
    the ciphertext produced using AES. 

"""
##################################################
# Definitions
__author__ = "Cole Brooks"
___copyright__ = "Copyright 2021, github.com/Cole-Brooks"
__license__ = "Creative Commons - use it for whatever I don't care"

# Substitution box obtained from https://en.wikipedia.org/wiki/Rijndael_S-box
substitution_box = [
        [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ],
		[ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ],
		[ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ],
		[ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ],
		[ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ],
		[ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ],
		[ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ],
		[ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ],
		[ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ],
		[ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ],
		[ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ],
		[ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ],
		[ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ],
		[ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ],
		[ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ],
		[ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
]

# Inverse substitution box obtained from https://en.wikipedia.org/wiki/Rijndael_S-box
substitution_box_inverse = [
    [ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB ],
    [ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB ],
    [ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E ],
    [ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 ],
    [ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 ],
    [ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 ],
    [ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 ],
    [ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B ],
    [ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 ],
    [ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E ],
    [ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B ],
    [ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 ],
    [ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F ],
    [ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF ],
    [ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 ],
    [ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D ]
]

# Round constants obtained from the Round constants section of https://en.wikipedia.org/wiki/AES_key_schedule
round_constants = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

##################################################
# Functions
def is_power_of_two(i):
    """
    is_power_of_two

    helper function for determining if padding is needed to create square lists

    credit to https://www.geeksforgeeks.org/python-program-to-find-whether-a-no-is-power-of-two/
    """
    if (i == 0):
        return False
    while (i != 1):
        if (i % 2 != 0):
            return False
        i = i // 2
    return True

def convert_to_4_by_4(hex_val):
    """
    convert_to_4_by_4

    converts a string of 16 bytes into a 4 x 4 list of lists

    Parameters
    ---------------
    hex_val : string
        a 16 byte hex value to convert to a 4x4 block
        ex: 'a8eb124015cfcde6b795b56e10cb92a8'
        note: if any other length is put into this function, an exception will be raised

    Returns
    ---------------
    list of lists
        a 4x4 list of lists filled with hex_val
        ex: [ 
            [a8, 15, b7, 10]
            [eb, cf, 95, cb]
            [12, cd, b5, 92]
            [40, e6, 6e, a8]
        ]
    """
    if len(hex_val) != 32:
        raise Exception("convert_to_4_by_4 only functions with 16 byte inputs")
    
    # convert into an array of characters
    char_list = list(hex_val)
    two_char_list = []

    # combine elements to get an array of 2 digit characters
    # convert to int because it makes this easier
    for x in range(0, 32, 2):
        two_char_list.append(int(char_list[x] + char_list[x+1], 16))

    # Init a list of 4 lists (start with all Nones)
    ret_list = [[None for x in range(4)] for y in range(4)]

    index = 0
    for x in range(4):
        for y in range(4):
            ret_list[y][x] = two_char_list[index]
            index += 1

    return ret_list
        


def convert_string_to_array(string):
    """
    convert_string_to_array

    converts an input hex string into a 4x4 matrix

    Parameters
    ---------------
    string : string
        the string that you want to convert into a square matrix

    Returns
    ---------------
    list 
        a list of lists filled with the input strings pieces
    """
    if (len(string) % 2 != 0) or not is_power_of_two(len(string)):
        # TODO we'll need to do some padding
        print("padding needed")
    else: 
        # we know that the length is some power of two. No padding necessary
        print("no padding needed")

    if len(string) == 32:
        # easy base case - 1 block
        return convert_to_4_by_4(string)


def rot_word(byte):
    """
    rot_word

    performs a one-byte circular left shift on a word.

    Parameters
    ---------------
    byte : list
        the 4 byte word that needs to be shifted

    Returns
    ---------------
    list
        the shifted list of bytes produced
    """
    ret_byte = []
    try:
        for x in range(len(byte) -1):
            ret_byte.append(byte[x+1])
        ret_byte.append(byte[0])
    except Exception as e:
        print("Invalid input to rot_word")
    return ret_byte

def sub_byte(byte):
    """
    sub_byte

    performs one byte substitution using the substitution_box

    Parameters
    ---------------
    byte : int
        an integer which you would like to convert (0-255)
    
    Returns
    ---------------
    int
        the new integer 0-255 obtained from the substitution
    """
    hex_as_2_char = '{:02x}'.format(byte)

    y = int(hex_as_2_char[0], 16)   # the first digit of the byte in int
    x = int(hex_as_2_char[1],16)    # the second digit of the byte in int

    return substitution_box[y][x]

def sub_word(words):
    """
    sub_word

    performs a byte substitution on each byte of input word using the substitution_box

    Parameters
    ---------------
    word : list
        a list of 4 bytes, each in integer form that represents 2 words (2x2 byte array)
        ex: [0, 1, 2, 3]

    Returns
    ---------------
    list
        a list of 4 bytes representing the transformed word
        ex: [0, 1, 2, 3] -> [99, 124, 119, 123]
    """
    ret_words = []
    for word in words:
        # convert each byte into a 2 digit hex value and sub_byte
        ret_words.append(sub_byte(word))
    return ret_words

def xor(value_a, value_b):
    return value_a ^ value_b

"""
credit: mix_multiply_2, mix_multiply_3, and mix_columns were 
largely based off of what I learned reading this article:
https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with-python-8122af44ebf9
"""

def mix_multiply_2(val):
    s = val << 1
    s &= 0xff
    if(val & 128) != 0:
        s = s ^ 0x1b
    return s

def mix_multiply_3(val):
    return mix_multiply_2(val) ^ val

def transpose_matrix(X):
    result = [[X[j][i] for j in range(len(X))] for i in range(len(X[0]))]
    return result

def mix_column(col):
    ret = [
        mix_multiply_2(col[0]) ^ mix_multiply_3(col[1]) ^ col[2] ^ col[3],
        mix_multiply_2(col[1]) ^ mix_multiply_3(col[2]) ^ col[3] ^ col[0],
        mix_multiply_2(col[2]) ^ mix_multiply_3(col[3]) ^ col[0] ^ col[1],
        mix_multiply_2(col[3]) ^ mix_multiply_3(col[0]) ^ col[1] ^ col[2]
    ]
    return ret

def mix_columns(matrix):
    new_mat = [[]]*4
    for x in range(4):
        col = [matrix[y][x] for y in range(4)]
        col = mix_column(col)
        print("x: " + str(x) + ": Col: " + str(col))
        new_mat[x] = col
    ret_mat = transpose_matrix(new_mat)
    return ret_mat

def add_round_key(state, round_key):
    """
    add_round_key

    performs bitwise XOR between state and round key.

    Parameters
    ---------------
    state : list of lists (4x4 bytes)
        the block of bytes you want to xor 
    round_key : list of lists (4x4 bytes)
        the current round key

    Returns
    ---------------
    list of lists (4x4 bytes)
        the resulting array of bytes
    """
    resultant = [[None for x in range(4)] for y in range(4)]

    for x in range(4):
        print("x: " + str(x))
        for y in range(4):
            print("y: " + str(y))
            resultant[y][x] = state[y][x] ^ round_key[y][x]

    return resultant
class R_AES:
    def __init__(self, key_128):
        """
        Init the aes object. Note that this will only work with 128 bit keys (192 and 256 may be implemented one day {most likely not})
        """
        self.key_is_valid = True
        if len(key_128) != 16:
            print("PAY ATTENTION: rijndael_aes.py only supports 128 bit keys")
            self.key_is_valid = False
        else: 
            self.key_words = [[]]*44 # 10 round plus the given key gives us 4 * 11 keys
            self.set_key(key_128)

    def __str__(self):
        if self.key_is_valid:
            ret_str = "Words:\n"
            for x in range(len(self.key_words)):
                ret_str += (str(x) + ": " + str(self.key_words[x]) + "\n")

            ret_str += "\nRound Keys: "

            for x in range(len(self.round_keys)):
                ret_str += (str(x) + ": " + str(self.round_keys[x]) + "\n")
            return ret_str
        else:
            return "ATTENTION: YOUR AES OBJECT IS NOT INITIALIZED PROPERLY... Key is invalid. Only 128 bit keys supported."

    def set_key(self, key):
        # round keys are generated 
        self.key_words = self.key_expansion(key)
        self.round_keys = []
        for x in range(0, 44, 4):
            self.round_keys.append([self.key_words[x], self.key_words[x + 1], self.key_words[x + 2], self.key_words[x + 3]])

    def key_expansion(self, key): 
        """
        Use the provided key to create the round keys for eventually encrypting data

        Largely based on psuedocode on page 191 of Cryptography and Network Security Principles and Practice
        """
        words = [[]]*44

        # the first four words are generated using the provided key
        for x in range(4):
            words[x] = [key[4*x], key[4*x+1], key[4*x+2], key[4*x+3]]

        # the rest of the words use previous words, rot_word, sub_word, and round_constants
        for x in range(40):
            cur_word = x + 4 # offset so that we're not using x + 4 everywhere
            prev_word = words[cur_word-1]
            four_words_ago = words[cur_word-4]

            if x % 4 == 0:
                rotted = rot_word(prev_word)
                sub = sub_word(rotted)
                round_constant = round_constants[x // 4]

                for x in range(4):
                    prev_word[x] = xor(sub[x], round_constant)


            xored = []
            for x in range(4):
                xored.append(xor(four_words_ago[x], prev_word[x]))

            words[cur_word] = [xored[0], xored[1], xored[2], xored[3]]

        return words

    def encrypt_one_block(plaintext):
        """
        encrypt_one_block

        should encrypt 16 byte input via aes 128

        Parameters
        ---------------
        plaintext: string
            16 byte hex string (32 chars)

        Returns
        ---------------
        string
            the ciphertext produced via aes 128
        """

        return
##################################################################
# Driver

# test key generated via random byte generator (random.org/bytes/)
# note that this implementation will only support 128 bit keys, meaning there 
# should always be exactly 10 round keys (plus original key)

test_key = [
    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x9b
]

aes = R_AES(test_key)

# print(str(aes))

# run unit tests with python -m unittest test_aes.py

# print("----------------DEBUG--------------------")
# print("----------------END DEBUG----------------")
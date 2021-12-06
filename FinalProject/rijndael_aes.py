"""
    My implementation of rijndael aes, written for Cryptography (Fall 2021)

    This program will be able to take an input from the user via command line, and provide
    the ciphertext produced using AES. 

    It will also be able to convert from ciphertext to plaintext. Again using AES

    Note that this program only currently supports 128 bit keys.
"""
##################################################
# Definitions
__author__ = "Cole Brooks"
___copyright__ = "Copyright 2021, github.com/Cole-Brooks"
__license__ = "Creative Commons - use it for whatever I don't care"

from aes_consts import *

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
        
def convert_from_4_by_4(mat):
    """
    convert_from_4_by_4

    the functional inverse of convert_to_4_by_4

    Parameters
    ---------------
    list of lists
        a 4x4 list of lists filled with hex_val
        ex: [ 
            [a8, 15, b7, 10]
            [eb, cf, 95, cb]
            [12, cd, b5, 92]
            [40, e6, 6e, a8]
        ]

    Returns
    ---------------
    hex_val : string
        a 16 byte hex value to convert to a 4x4 block
        ex: 'a8eb124015cfcde6b795b56e10cb92a8'
    """
    ret_str = ""
    for x in range(4):
        for y in range(4):
            ret_str = ret_str + '{:02x}'.format(mat[y][x])
            
    return ret_str

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
    if len(string) == 32:
        return convert_to_4_by_4(string)
    else:
        # if string is the wrong length this function isn't going to handle it
        raise ValueError

def convert_array_to_string(mat):
    return convert_from_4_by_4(mat)

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

def i_sub_byte(byte):
    """
    i_sub_byte

    A functional inverse of sub_byte
    performs one byte substitution using the substitution_box_inverse

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

    return substitution_box_inverse[y][x]

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

def i_sub_word(words):
    """
    i_sub_word

    functional inverse of sub_word
    """
    ret_words = []
    for word in words:
        # convert each byte into a 2 digit hex value and sub_byte
        ret_words.append(i_sub_byte(word))
    return ret_words

def xor(value_a, value_b):
    # print("Value A: " + str(value_a))
    # print("Value B: " + str(value_b))
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
        new_mat[x] = col
    ret_mat = transpose_matrix(new_mat)
    return ret_mat

def i_mix_columns(matrix):
    """
    i_mix_columns

    functional inverse to mix_columns
    """
    unmixed = matrix
    for x in range(3):
        unmixed = mix_columns(unmixed)
    return unmixed

def multi_rotate(l, n):
    ret_val = l
    for x in range(n):
        ret_val = rot_word(ret_val)
    return ret_val

def matrix_shift_rows(mat):
    ret_mat = []
    for x in range(4):
        ret_mat.append(multi_rotate(mat[x], x))
    return ret_mat

def i_matrix_shift_rows(mat):
    """
    i_matrix_shift_rows

    functional inverse of matrix_shift_rows


    """
    ret_mat = []
    ret_mat.append(mat[0])
    ret_mat.append(multi_rotate(mat[1], 3))
    ret_mat.append(multi_rotate(mat[2], 2))
    ret_mat.append(multi_rotate(mat[3], 1))
    return ret_mat

def matrix_sub_bytes(mat):
    """
    matrix_sub_bytes

    substitutes all the bytes in a matrix using the substitution box
    """
    resultant = [[None for x in range(4)] for y in range(4)]
    for y in range(4):
        for x in range(4):
            resultant[y][x] = sub_byte(mat[y][x])
    return resultant      

def i_matrix_sub_bytes(mat):
    """
    i_matrix_sub_bytes

    functional inverse to matrix_sub_bytes
    """
    resultant = [[None for x in range(4)] for y in range(4)]
    for y in range(4):
        for x in range(4):
            resultant[y][x] = i_sub_byte(mat[y][x])
    return resultant  

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
        for y in range(4):
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

    def encrypt_one_block(self,plaintext):
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
        state = convert_string_to_array(plaintext)
        
        # print("State after converting to array: " + str(len(test)))        
        # the first round is just adding a round key, according to page 195
        # note the first round key is just the given key
        state = add_round_key(state, self.round_keys[0])

        # for rounds 1 - 9 we do the full process
        # subbytes, shiftrows, mixcolumns
        for x in range(1, 10):
            state = matrix_sub_bytes(state)
            state = matrix_shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[x])

        # for the last round we don't mix the colums but we do everything else
        state = matrix_sub_bytes(state)
        state = matrix_shift_rows(state)
        state = add_round_key(state, self.round_keys[10])

        state = convert_array_to_string(state)
        return state

    def decrypt_one_block(self, ciphertext):
        state = convert_string_to_array(ciphertext)
        # start by adding the last round key
        state = add_round_key(state, self.round_keys[10])

        # For rounds 1 - 9 we do the full inverse process
        for x in range(1,10):
            state = i_matrix_shift_rows(state)
            state = i_matrix_sub_bytes(state)
            state = add_round_key(state, self.round_keys[10-x])
            state = i_mix_columns(state)

        # For round 10 we don't mix the columns
        state = i_matrix_shift_rows(state)
        state = i_matrix_sub_bytes(state)
        state = add_round_key(state, self.round_keys[0])

        state = convert_array_to_string(state)
        return state

    def encrypt(self, plaintext):
        ct = ""
        plaintext = plaintext + const_padding_string # always add padding so we can get rid of it at the end

        # handle padding
        while len(plaintext) % 32 != 0:
            plaintext = plaintext + "0"
            
        plaintext_block_list = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
        for block in plaintext_block_list:
            ct = ct + self.encrypt_one_block(block)
        
        return ct

    def decrypt(self, ciphertext):
        pt = ""
        ciphertext_block_list = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

        for block in ciphertext_block_list:
            pt = pt + self.decrypt_one_block(block)
        ba = bytearray.fromhex(pt.split(const_padding_string,1)[0])
        return(ba.decode())
##################################################################
# Driver

# test key generated via random byte generator (random.org/bytes/)
# note that this implementation will only support 128 bit keys, meaning there 
# should always be exactly 10 round keys (plus original key)

test_key = [
    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x9b
]

# run unit tests with python -m unittest test_aes.py

# print("----------------DEBUG--------------------")
# print("----------------END DEBUG----------------")
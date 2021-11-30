from rijndael_aes import *
import unittest

class unit_tests(unittest.TestCase):
    """
    tests basic functions involved in writing rijndael_aes
    """
    def test_rot_word(self):
        """
        rot_word should return the shifted version of the word, ex [a, b, c, d] -> [b, c, d, a]
        and should work for multiple iterations, ie rot_word x2 [a, b, c, d] -> [c, d, a, b]
        """
        byte = ['a', 'b', 'c', 'd']
        self.assertEqual(rot_word(byte), ['b', 'c', 'd', 'a'])
        self.assertEqual(rot_word(rot_word(byte)), ['c', 'd', 'a', 'b'])
        self.assertEqual(rot_word(rot_word(rot_word(byte))), ['d', 'a', 'b', 'c'])
        self.assertEqual(rot_word(rot_word(rot_word(rot_word(byte)))), byte)

        # test with hex values
        byte = [0x01, 0x02, 0x03, 0x04]
        self.assertEqual(rot_word(byte), [0x02, 0x03, 0x04, 0x01])

        # test with int values
        byte = [16, 203, 146, 168]
        self.assertEqual(rot_word(byte), [203, 146, 168, 16])
    def test_multi_rotate(self):
        """
        multirotate should have the same functionality as rot_word, but 
        with the added parameter of how many times to rotate the word
        """
        byte = ['a', 'b', 'c', 'd']
        self.assertEqual(multi_rotate(byte,1), ['b', 'c', 'd', 'a'])
        self.assertEqual(multi_rotate(byte,2), ['c', 'd', 'a', 'b'])
        self.assertEqual(multi_rotate(byte,3), ['d', 'a', 'b', 'c'])
        self.assertEqual(multi_rotate(byte,4), byte)

        # test with int values
        byte = [16, 203, 146, 168]
        self.assertEqual(multi_rotate(byte,1), [203, 146, 168, 16])
        self.assertEqual(multi_rotate(byte,2), [146, 168, 16, 203])
        self.assertEqual(multi_rotate(byte,3), [168, 16, 203, 146])
        self.assertEqual(multi_rotate(byte,4), byte)

    def test_matrix_shift_rows(self):
        """
        matrix shift rows should shift the rows of a matrix in accordance with aes
        row 1 should not be shifted
        row 2 should be shifted by 1
        row 3 should be shifted by 2
        row 4 should be shifted by 3
        test case found on page 195 of textbook
        """
        test_mat = [[171,139,137,53],[216,64,127,241],[24,63,240,252],[228,78,47,196]]
        expected_mat = [[171,139,137,53],[64,127,241,216],[240,252,24,63],[196,228,78,47]]
        self.assertEqual(matrix_shift_rows(test_mat), expected_mat)

    def test_sub_byte(self):
        """
        sub_byte should return the substituted byte from the substitution table.

        Tests every value from 0-255
        """
        test_box = sum(substitution_box, [])
        for x in range(255):
            self.assertEqual(test_box[x], sub_byte(x))

    def test_matrix_sub_bytes(self):
        """
        matrix_sub_bytes should return a matrix with substituted bytes from the substitution box.
        """
        test_mat = [[14,206,242,217],[45,114,107,43],[52,37,23,85],[174,182,78,136]]
        expected = [[171,139,137,53],[216,64,127,241],[24,63,240,252],[228,78,47,196]]

        """
        NOTE: In testing this function I believe that I found an error on page 195 of the text book. Admitedly I have an old version
        """
        self.assertEqual(matrix_sub_bytes(test_mat), expected)

    def test_sub_words(self):
        """
        sub_words should return the substituted values for 2 words (2x2 byte array)

        Tests every value from 0-255
        """
        test_box = sum(substitution_box, [])
        for a in range(255):
            b = (a + 1) % 255
            c = (a + 2) % 255
            d = (a + 3) % 255

            test_words = [a, b, c, d]
            expected = [test_box[a], test_box[b], test_box[c], test_box[d]]

            self.assertEquals(expected, sub_word(test_words))

    def test_xor(self):
        """
        xor shouold return the bitwise xor of 2 integer inputs
        """
        expected_values = [
                    0,   240,   0,      255,    10,     83
        ]
        input_a = [ 0,   15,    255,    255,    20,     75 ]
        input_b = [ 0,   255,   255,    0,      30,     24 ]
        for x in range(len(expected_values)):
            self.assertEqual(xor(input_a[x], input_b[x]), expected_values[x])

    def test_convert_to_4_by_4(self):
        input_values = '000102030405060708090a0b0c0d0e0f'
        expected_output = [
            [0, 4, 8,   12],
            [1, 5, 9,   13],
            [2, 6, 10,  14],
            [3, 7, 11,  15]
        ]
        self.assertEquals(convert_to_4_by_4(input_values), expected_output)

    def test_convert_string_to_array_one_block(self):
        """
        convert_string_to_array should return the same value as convert_to_4_by_4 
        if the input is a single block (16 bytes)
        """
        input_values = '000102030405060708090a0b0c0d0e0f'
        expected_output = [
            [0, 4, 8,   12],
            [1, 5, 9,   13],
            [2, 6, 10,  14],
            [3, 7, 11,  15]
        ]
        self.assertEquals(convert_string_to_array(input_values), expected_output)

    def test_add_round_key(self):
        """
        add_round_key should return the xored matrix resultant of its two inputs
        test case is found in textbook (page 189)
        """
        input_state = [[71,64,163,76],[55,212,112,159],[148,228,58,66],[237,165,166,188]]
        input_round_key = [[172, 25, 40, 87],[119, 250, 209, 92],[102, 220, 41, 0],[243, 33, 65, 106]]
        expected = [[235,89,139,27],[64,46,161,195],[242,56,19,66],[30,132,231,214]]

        self.assertEqual(add_round_key(input_state, input_round_key), expected)

    # def test_aes(self):
    #     good_key = [
    #         0xe8, 0xeb, 0x12, 0x40, 0x15, 0xcf, 0xcd, 0xe6, 0xb7, 0x95, 0xb5, 0x6e, 0x10, 0xcb, 0x92, 0xa8
    #     ]
    #     bad_key = [
    #         0x01, 0xe8, 0xeb, 0x12, 0x40, 0x15, 0xcf, 0xcd, 0xe6, 0xb7, 0x95, 0xb5, 0x6e, 0x10, 0xcb, 0x92, 0xa8
    #     ]
    #     aes = R_AES()

if __name__ == '__main__':
    unittest.main()

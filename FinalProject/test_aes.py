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

        byte = [0x01, 0x02, 0x03, 0x04]
        self.assertEqual(rot_word(byte), [0x02, 0x03, 0x04, 0x01])

    def test_sub_byte(self):
        """
        sub_byte should return the substituted byte from the substitution table.

        Tests every value from 0-255
        """
        test_box = sum(substitution_box, [])
        for x in range(255):
            self.assertEqual(test_box[x], sub_byte(x))

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

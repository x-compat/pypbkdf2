import unittest

import pypbkdf2

class TestEnv(unittest.TestCase):

    def test_to_return_true(self):
        expected = True

        p = pypbkdf2.PyPBKDF2(salt_size=20)
        res = p.hash_password('12345')
        cipher_text = res[0]
        salt = res[1]

        valid = p.verify_password('12345', cipher_text, salt)
        self.assertEqual(expected, valid, msg='test should return True')
    
    def test_to_return_false(self):
        expected = False

        p = pypbkdf2.PyPBKDF2(salt_size=20)
        res = p.hash_password('1234')
        cipher_text = res[0]
        salt = res[1]

        valid = p.verify_password('12345', cipher_text, salt)
        self.assertEqual(expected, valid, msg='test should return False')
    
    def test_verify_should_return_true(self):
        expected = True

        p = pypbkdf2.PyPBKDF2(salt_size=20)
        cipher_text = 'a4LY3oYNM3iVpN4iMwj8xsibVyheld+pnsuLc8V6/1kEQpG3pB260wivI8q6fdkYkSiFArOvZCkyNkHRoAQy+g=='
        salt = 'l06TwZTNNEbjICeKt9Fr'
        
        valid = p.verify_password('12345', cipher_text, salt)
        self.assertEqual(expected, valid, msg='test should return True')


if __name__ == '__main__':
    unittest.main()
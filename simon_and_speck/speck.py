""" Speck implementation in python """


class Speck:
    """Implementation of speck in python"""

    def __init__(self, key: int, key_size: int = 128, block_size: int = 64) -> None:

        parameters = {32: {64: [4, 7, 22]},
                      48: {72: [3, 8, 22],
                           96: [4, 8, 23]},
                      64: {96: [3, 8, 26],
                           128: [4, 8, 27]},
                      96: {96: [2, 8, 28],
                           144: [3, 8, 29]},
                      128: {128: [2, 8, 32],
                            192: [3, 8, 33],
                            256: [4, 8, 34]}}

        self.block_size = block_size
        self.key_size = key_size
        self.key = key
        self.word_size = block_size // 2
        try:
            [self.number_of_keywords, self.alpha,
                self.number_of_rounds] = parameters[block_size][key_size]
        except KeyError:
            print("Invalid paramters")
            exit()
        self.beta = self.alpha - 5

        self.mask = (2 ** self.word_size) - 1
        self.mask_sub = (2 ** self.word_size)

        self.key = self.key & ((2 ** self.key_size) - 1)

        self.keys = [self.key & self.mask]
        _l = [(self.key >> (_x * self.word_size)) &
              self.mask for _x in range(1, self.number_of_keywords)]

        for i in range(self.number_of_rounds - 1):
            l_new = (
                ((self.keys[i] + self.right_shift(_l[i], self.alpha)) & self.mask) ^ i) & self.mask
            _l.append(l_new)
            k_new = (self.left_shift(
                self.keys[i], self.beta) ^ _l[-1]) & self.mask
            self.keys.append(k_new)

    def right_shift(self, value: int, alpha: int):
        """Right shifts the value by alpha

        Args:
            value (int): value to shift
            alpha (int, optional): Amount to be shifted by. Defaults to alpha.

        Returns:
            int: right shifted value
        """
        return ((value << (self.word_size - alpha)) + (value >> alpha)) & self.mask

    def left_shift(self, value: int, beta: int):
        """left shifts the value by alpha

        Args:
            value (int): value to shift
            beta (int, optional): Amount to be shifted by. Defaults to beta.

        Returns:
            int: left shifted value
        """
        return ((value >> (self.word_size - beta)) + (value << beta)) & self.mask

    def encrypt_function(self, _x, _y):
        """encrypts the upper and lower words _x and _y

        Args:
            _x (int): upperword
            _y (int): lowerword

        Returns:
            (int, int): encrypted upper and lower words
        """
        for i in range(self.number_of_rounds):
            _x = ((self.right_shift(_x, self.alpha) + _y)
                  & self.mask) ^ self.keys[i]
            _y = self.left_shift(_y, self.beta) ^ _x
        return _x, _y

    def decrypt_function(self, _x, _y):
        """decrypts the upper and lower words _x and _y

        Args:
            _x (int): upperword
            _y (int): lowerword

        Returns:
            (int, int): decrypted upper and lower words
        """
        for q in reversed(self.keys):
            _y = self.right_shift(_x ^ _y, self.beta)
            x_sub = (((_x ^ q) - _y) + self.mask_sub) % self.mask_sub
            _x = self.left_shift(x_sub, self.alpha)
        return _x, _y

    def encrypt(self, _plaintext):
        """Encrypts plaintext using Simon

        Args:
            _plaintext (string): plaitext to encrypt

        Returns:
            List(int): encrypted message
        """
        plaintext_binary = 0
        count = self.block_size // 32
        cipher = []
        counter = -1

        for _c in bytearray(_plaintext, 'utf-8'):

            plaintext_binary = (plaintext_binary << 32) + _c
            counter += 1

            if counter % count == count - 1:
                _b = (plaintext_binary >> self.word_size) & self.mask
                _a = plaintext_binary & self.mask
                _b, _a = self.encrypt_function(_b, _a)
                cipher.append((_b << self.word_size) + _a)
                plaintext_binary = 0

        if plaintext_binary != 0:
            _b = (plaintext_binary >> self.word_size) & self.mask
            _a = plaintext_binary & self.mask
            _b, _a = self.encrypt_function(_b, _a)
            cipher.append((_b << self.word_size) + _a)
            plaintext_binary = 0

        return cipher

    def decrypt(self, _ciphertext):
        """Decrypts given ciphertext

        Args:
            _ciphertext (List(int)): Given cyphertext

        Returns:
            string: Decrypted message
        """
        text = ""

        for cipher in reversed(_ciphertext):

            _b = (cipher >> self.word_size) & self.mask
            _a = cipher & self.mask
            _b, _a = self.decrypt_function(_b, _a)
            text = self.ascii_to_string((_b << self.word_size) + _a) + text

        return text

    def ascii_to_string(self, string_ascii):
        """Converts ascii numbers to string

        Args:
            string_ascii (int): ascii numbers for characters concatenated together

        Returns:
            string: resultant string
        """
        result = ""
        while string_ascii > 0:
            result = chr(string_ascii & ((2 ** 32) - 1)) + result
            string_ascii = string_ascii >> 32
        return result


if __name__ == "__main__":
    s = Speck(10)
    print(s.key)
    plaintext = "This is _a test to check if encryption and decryption are working or not"

    _ciphertext = s.encrypt(plaintext)

    print("_ciphertext =", _ciphertext)

    plaintext = s.decrypt(_ciphertext)

    print("plaintext =", plaintext)

class speck:

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
        except:
            print("Invalid paramters")
            exit()
        self.beta = self.alpha - 5

        self.mask = (2 ** self.word_size) - 1
        self.mask_sub = (2 ** self.word_size)

        self.key = self.key & ((2 ** self.key_size) - 1)

        self.keys = [self.key & self.mask]
        l = [(self.key >> (x * self.word_size)) &
             self.mask for x in range(1, self.number_of_keywords)]

        for i in range(self.number_of_rounds - 1):
            l_new = (
                ((self.keys[i] + self.right_shift(l[i], self.alpha)) & self.mask) ^ i) & self.mask
            l.append(l_new)
            k_new = (self.left_shift(
                self.keys[i], self.beta) ^ l[-1]) & self.mask
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

    def encrypt_function(self, x, y):
        """encrypts the upper and lower words x and y

        Args:
            x (int): upperword
            y (int): lowerword

        Returns:
            (int, int): encrypted upper and lower words
        """
        for i in range(self.number_of_rounds):
            x = ((self.right_shift(x, self.alpha) + y)
                 & self.mask) ^ self.keys[i]
            y = self.left_shift(y, self.beta) ^ x
        return x, y

    def decrypt_function(self, x, y):
        """decrypts the upper and lower words x and y

        Args:
            x (int): upperword
            y (int): lowerword

        Returns:
            (int, int): decrypted upper and lower words
        """
        for q in reversed(self.keys):
            y = self.right_shift(x ^ y, self.beta)
            x_sub = (((x ^ q) - y) + self.mask_sub) % self.mask_sub
            x = self.left_shift(x_sub, self.alpha)
        return x, y

    def encrypt(self, plaintext):

        plaintext_binary = 0
        count = self.block_size // 32
        cipher = []
        counter = -1

        for c in bytearray(plaintext, 'utf-8'):

            plaintext_binary = (plaintext_binary << 32) + c
            counter += 1

            if counter % count == count - 1:
                b = (plaintext_binary >> self.word_size) & self.mask
                a = plaintext_binary & self.mask
                b, a = self.encrypt_function(b, a)
                cipher.append((b << self.word_size) + a)
                plaintext_binary = 0

        if plaintext_binary != 0:
            b = (plaintext_binary >> self.word_size) & self.mask
            a = plaintext_binary & self.mask
            b, a = self.encrypt_function(b, a)
            cipher.append((b << self.word_size) + a)
            plaintext_binary = 0

        return cipher

    def decrypt(self, ciphertext):

        text = ""

        for cipher in reversed(ciphertext):

            b = (cipher >> self.word_size) & self.mask
            a = cipher & self.mask
            b, a = self.decrypt_function(b, a)
            text = self.ascii_to_string((b << self.word_size) + a) + text

        return text

    def ascii_to_string(self, string_ascii):

        result = ""
        while string_ascii > 0:
            result = chr(string_ascii & ((2 ** 32) - 1)) + result
            string_ascii = string_ascii >> 32
        return result


if __name__ == "__main__":
    s = speck(10)
    print(s.key)
    plaintext = "This is a test to check if encryption and decryption are working or not"

    ciphertext = s.encrypt(plaintext)

    print("ciphertext =", ciphertext)

    plaintext = s.decrypt(ciphertext)

    print("plaintext =", plaintext)

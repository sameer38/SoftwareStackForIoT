class simon:

    def right_shift(self, value: int, alpha: int):
        """Right shifts the value by alpha

        Args:
            value (int): value to shift
            alpha (int, optional): Amount to be shifted by. Defaults to ALPHA.

        Returns:
            int: right shifted value
        """
        return ((value << (self.word_size - alpha)) + (value >> alpha)) & self.mask

    def left_shift(self, value: int, beta: int):
        """left shifts the value by alpha

        Args:
            value (int): value to shift
            beta (int, optional): Amount to be shifted by. Defaults to BETA.

        Returns:
            int: left shifted value
        """
        return ((value >> (self.word_size - beta)) + (value << beta)) & self.mask

    def __init__(self, key: int, key_size: int = 128, block_size: int = 64) -> None:

        parameters = {32: {64: [4, 0, 32]},
                      48: {72: [3, 0, 36],
                           96: [4, 1, 36]},
                      64: {96: [3, 2, 42],
                           128: [4, 3, 44]},
                      96: {96: [2, 2, 52],
                           144: [3, 3, 54]},
                      128: {128: [2, 2, 68],
                            192: [3, 3, 69],
                            256: [4, 4, 72]}}

        self.block_size = block_size
        self.key_size = key_size
        self.key = key
        self.word_size = block_size // 2
        try:
            [self.number_of_keywords, self.j,
                self.number_of_rounds] = parameters[block_size][key_size]
        except:
            print("Invalid paramters")
            exit()

        self.z = [0b01100111000011010100100010111110110011100001101010010001011111,
                  0b01011010000110010011111011100010101101000011001001111101110001,
                  0b11001101101001111110001000010100011001001011000000111011110101,
                  0b11110000101100111001010001001000000111101001100011010111011011,
                  0b1111011100100101001100001110100000010001101101011001111]

        self.mask = (2 ** self.word_size) - 1

        self.key = self.key & ((2 ** self.key_size) - 1)

        self.keys = [(self.key >> (x * self.word_size)) &
                     self.mask for x in range(self.number_of_keywords)]

        for i in range(self.number_of_keywords, self.number_of_rounds):
            tmp = self.right_shift(self.keys[i-1], 3)
            if self.number_of_keywords == 4:
                tmp = (tmp ^ self.keys[i - 3]) & self.mask
            tmp = (tmp ^ self.right_shift(tmp, 1)) & self.mask

            z_tmp = (
                (self.z[self.j] >> ((i - self.number_of_keywords) % 62)) & 1) & self.mask

            k_new = (((~self.keys[i - self.number_of_keywords]) & self.mask)
                     ^ ((tmp ^ ((z_tmp ^ 3) & self.mask)) & self.mask)) & self.mask

            self.keys.append(k_new)

    def encrypt_function(self, x, y):

        for i in range(self.number_of_rounds):
            tmp = x
            x = y ^ (self.left_shift(x, 1) & self.left_shift(
                x, 8)) ^ self.left_shift(x, 2) ^ self.keys[i]
            y = tmp

        return x, y

    def decrypt_function(self, x, y):

        for k in reversed(self.keys):
            tmp = x
            x = y ^ (self.left_shift(x, 1) & self.left_shift(
                x, 8)) ^ self.left_shift(x, 2) ^ k
            y = tmp

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
                cipher.append((b << s.word_size) + a)
                plaintext_binary = 0

        if plaintext_binary != 0:
            b = (plaintext_binary >> self.word_size) & self.mask
            a = plaintext_binary & self.mask
            b, a = self.encrypt_function(b, a)
            cipher.append((b << s.word_size) + a)
            plaintext_binary = 0

        return cipher

    def decrypt(self, ciphertext):

        text = ""

        for cipher in reversed(ciphertext):

            b = (cipher >> self.word_size) & self.mask
            a = cipher & self.mask
            a, b = self.decrypt_function(a, b)

            text = self.ascii_to_string((b << self.word_size) + a) + text

        return text

    def ascii_to_string(self, string_ascii):

        result = ""
        while string_ascii > 0:
            result = chr(string_ascii & ((2 ** 32) - 1)) + result
            string_ascii = string_ascii >> 32
        return result


if __name__ == "__main__":
    s = simon(123412, 72, 48)
    print(s.key)
    plaintext = "This is a test to check if encryption and decryption are working or not"

    ciphertext = s.encrypt(plaintext)

    print("ciphertext =", ciphertext)

    plaintext = s.decrypt(ciphertext)

    print("plaintext =", plaintext)

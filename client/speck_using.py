""" Speck implementation in python """
import ctypes
from math import ceil


class Speck:
    """Implementation of speck in python"""

    def __init__(self, key: int) -> None:

        self.c_speck = ctypes.CDLL("./libspeck.so")

        self.c_speck.Speck128128KeySchedule.argtypes = [
            ctypes.c_uint64 * 2,
            ctypes.c_uint64 * 32,
        ]
        self.c_speck.Speck128128Encrypt.argtypes = [
            ctypes.c_uint64 * 2,
            ctypes.c_uint64 * 2,
            ctypes.c_uint64 * 32,
        ]
        self.c_speck.Speck128128Decrypt.argtypes = [
            ctypes.c_uint64 * 2,
            ctypes.c_uint64 * 2,
            ctypes.c_uint64 * 32,
        ]

        self.u8Array16 = ctypes.c_uint8 * 16
        self.u64Array2 = ctypes.c_uint64 * 2
        self.u64Array32 = ctypes.c_uint64 * 32

        lower_key = key & ((2**64) - 1)
        upper_key = (key >> 64) & ((2**64) - 1)

        self.key = self.u64Array2(upper_key, lower_key)

        self.keys = self.u64Array32()

        self.c_speck.Speck128128KeySchedule(self.key, self.keys)

    def encrypt(self, plaintext):
        """Encrypts plaintext using Simon

        Args:
            _plaintext (string): plaitext to encrypt

        Returns:
            List(int): encrypted message
        """
        size = ceil(len(plaintext) / 8)
        if size % 2 == 1:
            size += 1

        type_ciphertext = ctypes.c_uint64 * size

        self.c_speck.encrypt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint64 * 32,
            type_ciphertext,
        ]

        self.c_speck.decrypt.argtypes = [
            ctypes.c_uint64 * 32,
            type_ciphertext,
            ctypes.c_int,
            ctypes.c_char_p,
        ]

        ciphertext = type_ciphertext()

        self.c_speck.encrypt(
            plaintext.encode("utf-8"), len(plaintext), self.keys, ciphertext
        )

        return list(ciphertext)

    def decrypt(self, ciphertext):
        """Decrypts given ciphertext

        Args:
            _ciphertext (List(int)): Given cyphertext

        Returns:
            string: Decrypted message
        """

        size = len(ciphertext)
        typeCt = ctypes.c_uint64 * size

        ciphertext = typeCt(*ciphertext)

        self.c_speck.decrypt.argtypes = [
            ctypes.c_uint64 * 32,
            typeCt,
            ctypes.c_int,
            ctypes.c_char_p,
        ]

        typePt = ctypes.c_char * (size * 8)

        plaintext = typePt()

        self.c_speck.decrypt(self.keys, ciphertext, size, plaintext)

        return plaintext.value.decode("utf-8")


if __name__ == "__main__":

    s = Speck(10)

    for i in range(1):
        plaintext = (
            "This is _a test to check if encryption and decryption are working or not"
        )

        _ciphertext = s.encrypt(plaintext)

        print("_ciphertext =", _ciphertext)

        plaintext = s.decrypt(_ciphertext)

        print("plaintext =", plaintext)

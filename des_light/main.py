#!/usr/bin/env pypy3

import os

import des  # https://pypi.org/project/des/

from secret import FLAG


# Shorten DES to only two rounds.
des.core.ROTATES = (1, 1)

key = des.DesKey(os.urandom(8))


def encrypt(plaintext, iv=None):
    ciphertext = key.encrypt(plaintext, padding=True, initial=iv)

    if iv is not None:
        return iv.hex() + ciphertext.hex()
    else:
        return ciphertext.hex()


def main():
    print("Welcome to the Data Encryption Service.")

    try:
        plaintext = bytes.fromhex(input("Enter some plaintext (hex): "))
    except ValueError:
        print("Please enter a hex string next time.")
        exit(0)
     
    print("Ciphertext:", encrypt(plaintext))
    print("Flag:", encrypt(FLAG.encode("ascii"), iv=os.urandom(8)))


if __name__ == "__main__":
    main()

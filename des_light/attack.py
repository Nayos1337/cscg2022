import os
import des
from collections import Counter

des.core.ROTATES = (1, 1)

from des.core import *
from des.base import *

def blockify(input):
    return [int.from_bytes(input[i: i + 8], "big") for i in range(0, len(input), 8)]

def unblockify(blocks):
    return b''.join(block.to_bytes(8, "big") for block in blocks)

# inverts a permutation
def invert(perm):
    iperm = [-1] * (max(perm) + 1)
    for i, p in enumerate(perm):
        if iperm[p] == -1:
            iperm[p] = i
    return iperm

F_INVERSE_PERMUTATION = invert(PERMUTATION)

# This calculates the output of the F-function using a
# plain and chipertext block pair. This only works for two round DES.
def calc_outputs(plaintext, ciphertext):

    # apply the initial permutation to get the input of the feistel network
    plaintext = permute(plaintext, 64, INITIAL_PERMUTATION)
    l0, r0 = plaintext >> 32, plaintext & 0xffffffff

    # apply the initial permutation to invert the final permutation at the end
    ciphertext = permute(ciphertext, 64, INITIAL_PERMUTATION)
    l2, r2 = ciphertext >> 32, ciphertext & 0xffffffff

    (r2, l2) = (l2, r2) # revert the swap of the blocks at the end of DES

    fr0 = l2 ^ l0 # F(r0, k0)
    fl2 = r2 ^ r0 # F(l2, k1)

    return ((fr0, r0), (fl2, l2))


# returns a dictonary which maps a sbox output to a set of
# all possible sbox inputs that produce that result
def possible_sbox_inputs(sbox):
    result = {i:set() for i in range(2 ** 4)}

    for input in range(2 ** 6):
        output = sbox[input & 0x20 | (input & 0x01) << 4 | (input & 0x1e) >> 1]

        result[output].add(input)

    return result

# calculates all possible 6-bit key chunks from the F input and output
def possible_subkey_chunks(f, inp, sbox_maps):
    f = permute(f, 32, F_INVERSE_PERMUTATION)
    inp = permute(inp, 32, EXPANSION)
    for i, sbox_map in enumerate(sbox_maps):
        f_chunk = f >> 28 - i * 4 & 0x0f
        inp_chunk = inp >> 42 - i * 6 & 0x3f
        possible = sbox_map[f_chunk]

        yield {inp_chunk ^ val for val in possible}

# constructs a key from the most common chunks
def construct_key(counters):
    key = 0
    for i, c in enumerate(counters):
        v, _ = c.most_common(1)[0]
        key |= v << (42 - 6 * i)
    return key

# calculates subkeys based on plaintext / ciphertext pairs
def extract_key(plaintexts, ciphertexts):
    # calculated once. used later in possible_subkey_chunks
    sbox_maps = [possible_sbox_inputs(sbox) for sbox in SUBSTITUTION_BOX]

    counters_k0 = [Counter() for _ in range(len(SUBSTITUTION_BOX))]
    counters_k1 = [Counter() for _ in range(len(SUBSTITUTION_BOX))]

    for plain, cipher in zip(plaintexts, ciphertexts):
        # calculate f inputs and outputs for the current plaintext / ciphertext pair
        (fr0, r0), (fl2, l2) = calc_outputs(plain, cipher)

        # update counters based on possible subkey values
        for counter, possible in zip(
                counters_k0, possible_subkey_chunks(fr0, r0, sbox_maps)
            ):
            counter.update(possible)

        for counter, possible in zip(
                counters_k1, possible_subkey_chunks(fl2, l2, sbox_maps)
            ):
            counter.update(possible)

    # reconstruct the subkeys
    k0 = construct_key(counters_k0)
    k1 = construct_key(counters_k1)

    return (k0, k1)


def main():
    plain = os.urandom(8 * 5)  # random amount of plaintexts. seems to work fine most of the time

    if user := input(f"Plaintext (press enter to use {plain.hex()}): "):
        plain = bytes.fromhex(user)

    cipher = bytes.fromhex(input(f"Ciphertext: "))

    plaintexts = blockify(plain)
    ciphertexts = blockify(cipher)

    flag = bytes.fromhex(input(f"Flag: "))
    flag = blockify(flag)

    k0, k1 = extract_key(plaintexts, ciphertexts)

    # decrypt the flag
    iv, flag = flag[0], flag[1:]
    flag = unblockify(cbc(flag, ((k0, k1), ), iv, False))
    flag = flag[:-flag[-1]]

    print("Flag:",flag.decode('ascii'))



if __name__ == '__main__':
    main()

#!/usr/bin/env pypy3

import os
import sys
import des  # https://pypi.org/project/des/
import itertools
import random
from functools import cache

import des.core as des
from des.base import cbc

try:
    from tqdm import tqdm
except:
    tqdm = lambda x: x

from pwn import *

def blockify(data, blocksize=8):
    return [data[i:i+blocksize] for i in range(0, len(data), blocksize)]

def unblockify(blocks):
    return b''.join(block.to_bytes(8, "big") for block in blocks)

# derive the subkeys from the 58-bit key
def derive_keys_58(key):
    next_key = key >> 28, key & 0x0fffffff
    for bits in des.ROTATES:
        next_key = des.rotate_left(next_key[0], bits), des.rotate_left(next_key[1], bits)
        yield des.permute(next_key[0] << 28 | next_key[1], 56, des.PERMUTED_CHOICE2)

# inverts a permutation
# discarded bits have entry -1
def invert(perm):
    iperm = [-1] * (max(perm) + 1)
    for i, p in enumerate(perm):
        if iperm[p] == -1:
            iperm[p] = i
    return iperm

def active_sboxes(data):
    for i in range(8):
        inp = data >> 42 - i * 6 & 0x3f
        if inp != 0:
            yield i


def collect_information(plaintext):
    io = remote(sys.argv[1], 31337, ssl=True)
    io.sendline(plaintext.hex().encode())

    io.readuntil(b"Ciphertext: ")
    ciphertext = bytes.fromhex(io.readlineS())

    io.readuntil(b"Flag: ")
    flag = bytes.fromhex(io.readlineS())

    io.close()
    return ciphertext, flag


def construct_key(parts):
    key = 0
    for i, p in enumerate(parts):
        key |= p << (42 - 6 * i)
    return key

F_INVERSE_PERMUTATION = invert(des.PERMUTATION)
INVERSE_EXPANSION = invert(des.EXPANSION)
INVERSE_PERMUTATED_CHOICE2 = invert(des.PERMUTED_CHOICE2)

# bits of the 58-bit encryption key, that PERMUTED_CHOICE2
# discards and which therefore have to be brute forced
ENCRYPTION_KEY_HOLES = [2, 13, 18, 21, 31, 34, 38, 47]

des.SUBSTITUTION_BOX = list(des.SUBSTITUTION_BOX)

des.SUBSTITUTION_BOX[2] = (
     5,  8, 13,  6,  7,  2, 15,  4, 11, 14,  0,  3,  9, 12, 10,  1,
     3,  2, 15, 11,  1,  0, 12,  9, 13,  6,  7,  8, 14,  4,  5, 10,
     0, 15,  7, 14,  2,  9,  5, 12,  4, 11, 10,  1,  6, 13,  8,  3,
    12,  6,  1,  5, 14,  4,  3,  7,  0,  8, 15, 10,  2, 11, 13,  9,
)

des.SUBSTITUTION_BOX[3] = (
     4, 13,  6, 10, 12,  0, 14,  2, 15,  9,  8, 11,  5,  1,  7,  3,
     7,  9, 10, 11,  0, 14,  2, 12, 13,  4, 15,  6,  3,  5,  1,  8,
    10,  5,  0,  7,  6,  9,  4, 11,  8, 14,  2, 12,  1, 13,  3, 15,
     5,  3,  7,  1, 10,  6,  8,  4,  9, 15, 11,  0,  2, 14, 13, 12,
)

des.SUBSTITUTION_BOX[7] = (
     8,  0, 15,  7, 12,  2, 13,  5,  3, 10, 11,  6,  1, 14,  9,  4,
    11, 12,  3,  5,  9, 14,  1, 13,  7,  0,  4,  8, 15,  2,  6, 10,
     7,  9, 10,  0,  5, 11,  8, 14,  1,  4, 13,  2,  3,  6, 15, 12,
     9,  4,  8,  3,  1,  6, 10, 11,  0, 14,  5, 13,  2, 12,  7, 15,
)


class Characteristic2R:
    def __init__(self, in_delta, dl14, dr14):
        # all S-boxes, that get a non-zero input XOR
        sboxes = active_sboxes(des.permute(dr14, 32, des.EXPANSION))
        # possible changed bits after sboxes
        sbox_out = sum(0xf << 28 - 4 * i for i in sboxes)
        # all possibly non-zero bits in the F output
        f_out = des.permute(sbox_out, 32, des.PERMUTATION)
        # invert the mask => all definitly zero bits
        self.mask = 2 ** 32 + ~f_out

        self.dl14 = dl14
        self.dr14 = dr14

        self.in_delta = in_delta

    # return the input and output deltas to the F function
    # based on a pair
    def f_params(self, pair):
        delta = pair.delta()
        # swap
        drp, dlp = delta.cipher >> 32, delta.cipher & 0xffffffff
        return (dlp, drp ^ self.dr14)


    # check if a pair is right using the mask calculated in __init__
    def is_right_pair(self, pair):
        delta = pair.delta()
        # swap
        drp, dlp = delta.cipher >> 32, delta.cipher & 0xffffffff
        out_fr14 = dlp ^ self.dl14
        return delta.plain == self.in_delta and out_fr14 & self.mask == 0

class SBox:
    def __init__(self, box):
        self.box = box

    def __getitem__(self, v):
        return self.box[v & 0x20 | (v & 0x01) << 4 | (v & 0x1e) >> 1]

    # return a map which maps output deltas, to all possible inputs
    @cache
    def get_possible_values(self, in_delta):
        map = {i:[] for i in range(2 ** 4)}
        for m in range(2 ** 6):
            out_delta = self[m] ^ self[m ^ in_delta]
            map[out_delta].append(m)
        return map

class Sample:
    def __init__(self, plain, cipher=None):
        # these fields are the permuted plaintext / ciphertext
        # => input / output to the feistel network
        self.plain = plain
        self.cipher = cipher

    # return the plaintext to be encrypted
    def plaintext(self):
        plain = des.permute(self.plain, 64, des.INVERSE_PERMUTATION)
        return plain.to_bytes(8, "big")


    def set_ciphertext(self, cipher):
        cipher = int.from_bytes(cipher, "big")
        cipher = des.permute(cipher, 64, des.INITIAL_PERMUTATION)
        self.cipher = cipher

    def __xor__(self, other):
        if not isinstance(other, Sample):
            return NotImplemented

        return Sample(self.plain ^ other.plain, self.cipher ^ other.cipher)

    def __gt__(self, other):
        if not isinstance(other, Sample):
            return NotImplemented

        return self.plain > other.plain

    def __repr__(self):
        return f"Sample({self.plain:08x} -> {self.cipher:08x})"

class Pair:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def delta(self):
        return self.a ^ self.b

    def __repr__(self):
        delta = self.delta()
        return f"Pair(delta: {delta.plain:016x} -> {delta.cipher:016x})"

class Chunk:
    def __init__(self, seed, deltas):
        self.samples = []
        self.deltas = deltas
        d1, d2, d3 = deltas
        for i, j, k in itertools.product([0, d3], [0, d2], [0, d1]):
            self.samples.append(Sample(seed ^ i ^ j ^ k))

    def plaintext(self):
        return b''.join(sample.plaintext() for sample in self.samples)

    def set_ciphertext(self, cipher):
        for sample, block in zip(self.samples, blockify(cipher, blocksize=8)):
            sample.set_ciphertext(block)

    def pairs(self):
        for i in range(2 ** 3):
            for j in range(3):
                p = self.samples[i]
                q = self.samples[i ^ 1 << j]
                # yield permutation only once
                if p > q:
                    yield self.deltas[j], Pair(p, q)

class Chunks:
    def __init__(self, count, deltas):
        self.chunks = [
            Chunk(random.randint(0, 2 ** 64), deltas) for _ in range(count)
        ]

    def pairs(self):
        return itertools.chain.from_iterable(chunk.pairs() for chunk in self.chunks)

    def plaintext(self):
        return b''.join(chunk.plaintext() for chunk in self.chunks)

    def set_ciphertext(self, cipher):
        for chunk, block in zip(self.chunks, blockify(cipher, blocksize=8*8)):
            chunk.set_ciphertext(block)

class Subkey:
    def __init__(self):
        self.possible = [set(range(64)) for _ in range(8)]

    def update(self, i, possible):
        self.possible[i] = self.possible[i].intersection(possible)

    def count_possible(self):
        p = 1
        for poss in self.possible:
            p *= len(poss)
        return p

    def possible_subkeys(self):
        return itertools.product(*self.possible)

    def possible_enc_keys(self):
        for key in self.possible_subkeys():
            skeleton = construct_key(key)
            skeleton = des.permute(skeleton, 48, INVERSE_PERMUTATED_CHOICE2)
            for brute_force in range(2 ** 8):
                enc_key = skeleton
                for i, hole in enumerate(ENCRYPTION_KEY_HOLES):
                    if brute_force & (1 << i) != 0:
                        enc_key |= 1 << hole
                yield enc_key

# the amount of 8-byte samples the server has to encrypt.
# the higher the number the longer the server-side encryption,
# but the shorter the client-side the brute force
# 20k samples = 156kB encrypted data
SAMPLE_COUNT = 20_000

SBOXES = [SBox(box) for box in des.SUBSTITUTION_BOX]

CHARACTERISTICS = {
    0x00000004 << 32: Characteristic2R(0x00000004 << 32, 0x00020000,  0x00000004),
    0x00020000 << 32: Characteristic2R(0x00020000 << 32, 0x00400000,  0x00020000),
    0x00400000 << 32: Characteristic2R(0x00400000 << 32, 0x00000004,  0x00400000)
}

if len(sys.argv) != 2:
    print(f"Usage: ./{sys.argv[0]} <remote-host>")
    exit(1)

deltas = list(CHARACTERISTICS.keys())
subkey = Subkey()

random.seed(0xdeadbeef)
chunks = Chunks(SAMPLE_COUNT // 8, deltas)

plaintext = chunks.plaintext()
print("Starting encryption...")
ciphertext, flag = collect_information(plaintext)
print("Encryption done")
chunks.set_ciphertext(ciphertext)

# Analysis starts
for delta, pair in chunks.pairs():
    car = CHARACTERISTICS[delta]
    if car.is_right_pair(pair):
        in_delta, out_delta = car.f_params(pair)

        # sadly no use to us
        if in_delta == 0 or out_delta == 0:
            continue

        # one of the inputs to the F function
        f_input = pair.a.cipher & 0xffffffff
        f_input = des.permute(f_input, 32, des.EXPANSION)

        # input / output deltas of sboxes
        in_delta = des.permute(in_delta, 32, des.EXPANSION)
        out_delta = des.permute(out_delta, 32, F_INVERSE_PERMUTATION)

        for i, box in enumerate(SBOXES):

            part_delta_in  = in_delta >> 42 - i * 6 & 0x3f
            part_delta_out = out_delta >> 28 - i * 4 & 0x0f
            part_f_input = f_input >> 42 - i * 6 & 0x3f

            # all possible inputs to the sbox that could yield the right output delta
            possible = box.get_possible_values(part_delta_in)[part_delta_out]

            # all possible subkey parts for this sbox
            possible_subkeys = [pos ^ part_f_input for pos in possible]
            subkey.update(i, possible_subkeys)


print(f"There are {subkey.count_possible()} possible subkeys left")
print(f"That corresponds to {subkey.count_possible() * 256} possible encryption keys")
if subkey.count_possible() > 1024:
    print(f"Ooof... that's bad luck. Brute force will take a few minutes, but you can also just restart the script")

# example plaintext / ciphertext pair to test brute force against
sample = chunks.chunks[0].samples[0]
sample_plain = des.permute(sample.plain, 64, des.INVERSE_PERMUTATION)
sample_cipher = des.permute(sample.cipher, 64, des.INVERSE_PERMUTATION)

print("Starting brute force")
for enc_key in tqdm(subkey.possible_enc_keys()):
    subkeys = list(derive_keys_58(enc_key))
    if sample_cipher == des.encode_block(sample_plain, subkeys, True):
        break

print(f"The right encryption key was found: {enc_key:014x}")

# decrypt the flag
flag = blockify(flag)
flag = [int.from_bytes(chunk, "big") for chunk in flag]
iv, flag = flag[0], flag[1:]
flag = unblockify(cbc(flag, (subkeys, ), iv, False))
flag = flag[:-flag[-1]]

print("Flag:",flag.decode('ascii'))

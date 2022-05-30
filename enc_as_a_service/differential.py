#!/usr/bin/env pypy3

import os
import sys
import des.core as des  # https://pypi.org/project/des/

from collections import Counter

def invert(perm):
    iperm = [-1] * (max(perm) + 1)
    for i, p in enumerate(perm):
        if iperm[p] == -1:
            iperm[p] = i
    return iperm

F_INVERSE_PERMUTATION = invert(des.PERMUTATION)
INVERSE_EXPANSION = invert(des.EXPANSION)

# Use custom sbox values.
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


class SBox:
    def __init__(self, box):
        self.box = box
        self.table = {}
        self.counters = {}
        self.calc_distribution_table()


    def __getitem__(self, v):
        return self.box[v & 0x20 | (v & 0x01) << 4 | (v & 0x1e) >> 1]

    def calc_distribution_table(self):
        for delta in range(2 ** 6):
            counter = Counter()
            counter.update(self[m] ^ self[m ^ delta] for m in range(0, 2 ** 6))
            self.counters[delta] = counter
            self.table[delta] = dict(counter)

    def predict_out_delta(self, in_delta):
        (out_delta, p),  =  self.counters[in_delta].most_common(1)
        return (out_delta, p / 2 ** 6)

    def best_delta(self):
        best = (0, 0)
        for delta in range(1, 2 ** 6):
            square_error = sum(map(lambda x: x**2, self.table[delta].values()))
            if square_error > best[1]:
                best = (delta, square_error)

        out_delta, p = self.predict_out_delta(best[0])
        return best[0], out_delta, p


class Characteristic():
    def __init__(self, init_deltas, nrounds):
        self.input_deltas = init_deltas
        self.rounds = []
        self.probability = 1
        l, r = init_deltas
        for i in range(nrounds):
            vf, p = self.pass_delta_f(r)
            self.probability *= p
            l, r = (r, l ^ vf)
            self.rounds.append((l, r, p))


    def pass_delta_f(self, delta):
        global SBOXES
        delta = des.permute(delta, 32, des.EXPANSION)

        prob = 1
        delta_out = 0
        for i, box in enumerate(SBOXES):
            act = delta >> 42 - i * 6 & 0b111111
            d, p = box.predict_out_delta(act)
            delta_out = delta_out << 4 | d
            prob *= p

        delta_out = des.permute(delta_out, 32, des.PERMUTATION)

        return delta_out, prob

    def print(self):
        l, r = self.input_deltas
        print(f"\tinput:    {l:08x} {r:08x}")
        for i, (l,r,p) in enumerate(self.rounds):
            print(f"\tround {i+1:02d}: {l:08x} {r:08x} (p = {p:2.2f})")
        print(f"\t\t=> overall probability: {self.probability:2.4f}")


SBOXES = [SBox(box) for box in des.SUBSTITUTION_BOX]
CUSTOM_SBOXES = [2,3,7]

print("S-box differentials:")
for i in CUSTOM_SBOXES:
    in_delta, out_delta, p = SBOXES[i].best_delta()
    print(f"\tS-Box {i+1}: {in_delta} -> {out_delta} (p = {p:2.2f})")
print()

differentials = []
print("F-function differentials:")
for i in CUSTOM_SBOXES:
    in_delta, out_delta, _ = SBOXES[i].best_delta()
    in_delta = in_delta << (42 - i * 6)
    in_delta = des.permute(in_delta, 48, INVERSE_EXPANSION)
    out_delta = out_delta << (28 - i * 4)
    out_delta = des.permute(out_delta, 32, des.PERMUTATION)
    print(f"\t{in_delta:08x} -> {out_delta:08x}")
    differentials.append(in_delta)
print()

print("14-round Caracteristics:")
for diff in differentials:
    c = Characteristic((diff, 0), 14)
    c.print()

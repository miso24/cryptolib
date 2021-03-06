import functools
import math
import re

from collections import Counter
from typing import List, Tuple, Set
from cryptolib.util.ascii import (
    idx2lower,
    alphabet_idx,
)


english_freq = {
    'a': 0.084970, 'b': 0.014920, 'c': 0.022020, 'd': 0.042530,
    'e': 0.111620, 'f': 0.022280, 'g': 0.020150, 'h': 0.060940,
    'i': 0.075460, 'j': 0.001530, 'k': 0.012920, 'l': 0.040250,
    'm': 0.024060, 'n': 0.067490, 'o': 0.075070, 'p': 0.019290,
    'q': 0.000950, 'r': 0.075870, 's': 0.063270, 't': 0.093560,
    'u': 0.027580, 'v': 0.009780, 'w': 0.025600, 'x': 0.001500,
    'y': 0.019940, 'z': 0.000770,
}


def reduce_gcd(l: List[int]) -> int:
    return functools.reduce(math.gcd, l)


def n_gram(n: int, text: str) -> List[str]:
    rslt = []
    for i in range(len(text) - n + 1):
        rslt.append(
            text[i:i+n]
        )
    return rslt


def calc_freq_dist(counter: Counter, c_length: int) -> float:
    dist = 0.0
    for i in range(26):
        key = idx2lower(i)
        if key in counter:
            dist += ((counter[key] / c_length) - english_freq[key]) ** 2
        else:
            dist += english_freq[key] ** 2
    return dist


def freq_analysis(c: str, key_length: int) -> Tuple[str, float]:
    guess_key = ""
    avg_freq_dist = 0.0
    for pos in range(key_length):
        s = c[pos::key_length].lower()

        freq_dists = []
        for i in range(26):
            tmp_c = ''.join([idx2lower((alphabet_idx(char) - i) % 26)
                             for char in s])
            counter = Counter(tmp_c)
            dist = calc_freq_dist(counter, len(tmp_c))
            freq_dists.append(dist)
        lower_freq_dist = min(freq_dists)
        avg_freq_dist += lower_freq_dist
        guess_key += idx2lower(freq_dists.index(lower_freq_dist))
    return guess_key, avg_freq_dist/key_length


def kasisky_test(c: str, n_max: int = 10) -> Set[int]:
    candidates = set()
    # guess key length
    for n in range(2, n_max + 1):
        ng = n_gram(n, c)
        counter = Counter(ng)
        common_word, _ = counter.most_common()[1]

        indices = []
        before_pos, curr_pos = 0, 0
        while True:
            curr_pos = c.find(common_word, curr_pos)
            if curr_pos != -1:
                indices.append(curr_pos - before_pos)
                before_pos = curr_pos
                curr_pos += 1
            else:
                break

        if len(indices) <= 2:
            continue

        key_length = reduce_gcd(indices[1:])
        if 1 <= key_length <= 100:
            candidates.add(key_length)
    if len(candidates) == 0:
        raise ValueError('Kasisky test faild')
    return candidates


def break_cipher(cipher: str) -> Tuple[str, List[str]]:
    """

    Break vigenere cipher

    Args:
        cipher (str): encrypted

    Returns:
        str: the most probability key
        List[str]: key candidates
    """
    _cipher = re.sub(r'(\s|[^a-zA-Z])', '', cipher).lower()
    key_lens = kasisky_test(_cipher)
    guess_keys = {}
    for l in key_lens:
        key, dist = freq_analysis(_cipher, l)
        guess_keys[key] = dist
    best_key = sorted(guess_keys, key=lambda x: guess_keys[x])[0]
    return best_key, [*guess_keys.keys()]

"""
Utility functions for sphincs+

"""

from os import urandom
from math import ceil, floor, log2 as log


def trunc_int(x, l, base=2):
    '''
    Truncates the bit-string x to the first l bits
    x    : number to be truncated
    l    : number of bits to be truncated to in x
    base : optional argument denoting the base of variable x
    '''
    A = []
    while x > 0:
        A.append(x % base)
        x = (x - A[-1]) // base
    A.reverse()
    A = A[:l]
    x = 0
    A_len = len(A)
    for i in range(l):
        x += A[A_len - i - 1] * pow(base, i)
    return x


def toByte(x, y=None):
    """Returns y-byte string containing the binary representation of x in big-endian byte-order."""
    if y is None:
        y = ceil(x.bit_length() / 8)
    return x.to_bytes(y, byteorder="big")

# def fromByte(x):
#     return int.from_bytes(x, byteorder='big')


def concatenate(x, y, base=32):
    res = (x<<base) | (y)
    return res


def base_w(X, w, out_len):
    """
    Input: len_X-byte string X, int w, output length out_len
    Output: out_len int array basew
    """
    in_val, total, bits = 0, 0, 0
    basew = []
    for _ in range(out_len):
        if bits == 0:
            total = X[in_val]
            in_val += 1
            bits += 8
        bits -= log(w)
        basew.append( (total >> bits) and (w - 1) )
    return basew


def convert_to_int(msg):
    if type(msg) == str:
        msg = [ord(i) for i in msg]
    l = len(msg)
    num = 0
    base = 2 ** 8
    for i in range(l):
        num += msg[l - i - 1] * (base ** i)
    return num


def generate_seed(l):
    """WYgeneruj losową tablicę bajtów o długości l"""
    x = urandom(l)
    x = [i for i in x]
    return x


def sec_rand(x):
    """
    On input i returns i-bytes of cryptographically strong randomness
    """
    return convert_to_int(generate_seed(x))


def ht_PKgen(x):
    # to implement
    pass


def extract_bytes(H, lengths):
    # to implement
    pass

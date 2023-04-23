"""
Utility functions for sphincs+

"""

from os import urandom


def trunc(x, l):
    pass


def trunc_int(num, x, base=2):
    A = []
    while num > 0:
        A.append(num % base)
        num = (num - A[-1]) // base
    A.reverse()
    A = A[:x]
    num = 0
    l = len(A)
    for i in range(l):
        num += A[l - i - 1] * pow(base, i)
    return num


def toByte(x, y):
    """Returns y-byte string containing the binary representation of x in big-endian byte-order."""
    new_x = x.to_bytes(y, byteorder="big")
    return new_x


def base_w():
    """
    to implement
    """
    pass


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


def toByte(a, b):
    # to implement
    pass


def extract_bytes(H, lengths):
    # to implement
    pass

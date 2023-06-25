# from Crypto.Hash import SHAKE256
# from hashlib import shake_256 as SHAKE256
import hashlib
from utils import concatenate
from constants import *
from math import ceil, log2

"""
n - security parameter
m - message digest
"""
n = SECURITY_PARAM
m = MESSAGE_DIGEST


def shake256(msg, n = 26):
    # shake = SHAKE256.new()
    shake = hashlib.shake_256()
    if(type(msg) == int):
        try:
            l = ceil(log2(msg)) if msg != 0 else 1
        except:
            pass
        msg = msg.to_bytes(length = l, byteorder = 'big')
    shake.update(msg)
    return int(shake.hexdigest(256), 16)


def H_msg(R, PK_seed, PK_root, M):
    c = concatenate( concatenate(R, PK_seed), concatenate(PK_root, M) )
    return shake256(c, 8*m)


def PRF(seed, adrs):
    c = concatenate(seed, adrs)
    return shake256(c, 8*n)


def PRF_msg(SK_prf, OptRand, M):
    c = concatenate( concatenate(SK_prf, OptRand), M )
    return shake256(c, 8*n)


def F(PK_seed, adrs, M):
    c = concatenate( concatenate(PK_seed, adrs), M )
    return shake256(c, 8*n)


def H(PK_seed, adrs, M):
    c = concatenate( concatenate(PK_seed, adrs), M )
    return shake256(c, 8*n)


def T(PK_seed, adrs, M):
    c = concatenate( concatenate(PK_seed, adrs), M )
    return shake256(c, 8*n)

from Crypto.Hash import SHAKE256
from utils import concatenate
from constants import *

"""
n - security parameter
m - message digest
TODO: m an n values
"""
n = SECURITY_PARAM
m = MESSAGE_DIGEST


def shake256(msg, n = 26):
    shake = SHAKE256.new()
    shake.update(msg)
    res = shake.read(n).hex()
    return res

def H_msg(R, PK_seed, PK_root, M):
    c = concatenate( concatenate(R, PK_seed), concatenate(PK_root, M) )
    return shake256(c, 8*m)

def PRF(seed, adrs):
    c = concatenate( seed, adrs)
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

def T_l(PK_seed, adrs, M):
    c = concatenate( concatenate(PK_seed, adrs), M )
    return shake256(c, 8*n)
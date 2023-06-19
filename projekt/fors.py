from hash import PRF, H, F
from utils import *
from adrs import t_ADRS
from math import log2
from constants import FORS_LEAVES, FORS_TREES


class Fors():
    def __init__(self):
        '''
        • k: the number of private key sets, trees and indices computed from the input string.
        • t: the number of elements per private key set, number of leaves per hash tree and upper
        bound on the index values. The parameter t MUST be a power of 2. If t = 2^a, then the
        trees have height a and the input string is split into bit strings of length a.
        '''
        self.k = FORS_TREES
        self.t = FORS_LEAVES
        self.a = log2(self.t)

    def fors_SKgen(self, SK_seed, ADRS, idx):
        '''
        Input: 
            secret seed SK.seed, 
            address ADRS, 
            secret key index idx = it+j
        Output: 
            FORS private key sk
        '''
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(idx)
        sk = PRF(SK_seed, ADRS)
        return sk

    def fors_treehash(self, SK_seed, s, z, PK_seed, ADRS):
        '''
        Input: 
            Secret seed SK.seed, 
            start index s, 
            target node height z, 
            public seed PK.seed, 
            address ADRS
        Output: 
            n-byte root node - top node on Stack
        '''
        if s % (1 << z) != 0:
            return -1
        Stack = []
        for i in range(2**z):
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(s + i)
            sk = PRF(SK_seed, ADRS)
            node = F(PK_seed, ADRS, sk)
            ADRS.setTreeHeight(1)
            ADRS.setTreeIndex(s + i)
            while (not Stack.empty() and ADRS.getTreeHeight() == Stack.head()[1]):
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2)
                node = H(PK_seed, ADRS, concatenate(Stack.pop()[0], node))
                ADRS.setTreeHeight(ADRS.getTreeHeight() + 1)
            Stack.push((node, ADRS.getTreeHeight()))
        return Stack.pop()[0]

    def fors_PKgen(self, SK_seed, PK_seed, ADRS):
        '''
        Input: 
            Secret seed SK.seed, 
            public seed PK.seed, 
            address ADRS
        Output: 
            FORS public key PK
        '''
        forspkADRS = ADRS  # copy address to create FTS public key address
        root = [0 for i in range(self.k)]
        for i in range(self.k):
            root[i] = self.fors_treehash(SK_seed, i*self.t, self.a, PK_seed, ADRS)
        forspkADRS.setType(t_ADRS.FORS_ROOTS)
        forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = T_k(PK_seed, forspkADRS, root)
        return pk

    def fors_sign(self, M, SK_seed, PK_seed, ADRS):
        '''
        Input: 
            Bit string M, 
            secret seed SK.seed, 
            address ADRS, 
            public seed PK.seed
        Output: 
            FORS signature SIG_FORS
        '''
        # compute signature elements
        for i in range(self.k):
            # get next index
            idx = get_n_bin_digits(M, (i+1)*self.a - 1) - get_n_bin_digits(M, i*self.a)
            # pick private key element
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(i*self.t + idx)
            SIG_FORS = concatenate(SIG_FORS, PRF(SK_seed, ADRS))
            # compute auth path
            AUTH = [0 for _ in range(self.a)]
            for j in range(self.a):
                s = floor(idx / (2**j)) ^ 1
                AUTH[j] = self.fors_treehash(SK_seed, i * self.t + s * 2**j, j, PK_seed, ADRS)
            SIG_FORS = concatenate(SIG_FORS, AUTH)
        return SIG_FORS;

    def fors_pkFromSig(self, SIG_FORS, M, PK_seed, ADRS):
        '''
        Input: 
            FORS signature SIG_FORS, 
            (k lg t)-bit string M, 
            public seed PK.seed, 
            address ADRS
        Output: 
            FORS public key
        '''
        root = []
        for i in range(self.k):
            idx = get_n_bin_digits(M, (i+1)*self.a - 1) - get_n_bin_digits(M, i*self.a)
            sk = SIG_FORS.getSK(i)
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(i*self.t + idx)
            node_0 = F(PK_seed, ADRS, sk)
            auth = SIG_FORS.getAUTH(i)
            ADRS.setTreeIndex(i*self.t + idx)
            for j in range(self.a):
                ADRS.setTreeHeight(j+1)
                if ( (floor(idx / (2**j)) % 2) == 0 ):
                    ADRS.setTreeIndex(ADRS.getTreeIndex() / 2)
                    node_1 = H(PK_seed, ADRS, concatenate(node_0, auth[j]))
                else:
                    ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2)
                    node_1 = H(PK_seed, ADRS, concatenate(auth[j], node_0))
                node_0 = node_1
            root.append(node_0)
        forspkADRS = ADRS # copy address to create FTS public key address
        forspkADRS.setType(t_ADRS.FORS_ROOTS)
        forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = T_k(PK_seed, forspkADRS, root)
        return pk


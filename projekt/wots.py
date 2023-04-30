from utils import *
from numpy import copy
from Crypto.Hash import SHA256 as sha
from constants import *
from hash import *


class wots:
    """

    Parameters:

     - n : the security parameter; it is the message length as well as the length of a private key,
           public key, or signature element in bytes.
           The value of n determines the in- and output length of the tweakable hash function used for WOTS+.
           The value of n also determines the length of messages that can be processed by the WOTS+ signing algorithm

     - w : the Winternitz parameter; it is an element of the set {4, 16, 256}.

    """

    def __init__(self):
        self.n = SECURITY_PARAM
        self.w = WINTERNITZ_PARAM
        self.setup()

    def setup(self):
        self.len1 = ceil(8 * self.n / log(self.w))
        self.len2 = floor(log(self.len1 * (self.w - 1)) / log(self.w)) + 1
        self.len = self.len1 + self.len2

    def chain(self, X, i, s, PK_seed, ADRS):
        '''
        Input: 
            Input string X, 
            start index i, 
            number of steps s, 
            public seed PK_seed,
            address ADRS

        #Output: 
            value of F iterated s times on X

        '''
        if s == 0: return X
        if ((i + s) > (self.w - 1) ): return None
        tmp = self.chain(X, i, s - 1, PK_seed, ADRS);
        ADRS.setHashAddress(i + s - 1);
        tmp = F(PK_seed, ADRS, tmp);
        return tmp;

    def wots_SKgen(self, SK_seed, ADRS):
        '''
        Input: 
            secret seed SK.seed, 
            address ADRS

        Output: 
            WOTS+ private key sk
        '''
        sk = []
        for i in range(self.n):
            ADRS.setChainAddress(i)
            ADRS.setHashAddress(0)
            sk = []
            sk.append(PRF(SK_seed, ADRS))
        return sk
    
    def wots_PKgen(self, SK_seed, PK_seed, ADRS):
        '''
        Input: 
            secret seed SK.seed, 
            address ADRS, 
            public seed PK.seed

        Output: 
            WOTS+ public key pk
        '''
        wotspkADRS = copy(ADRS)
        tmp = []
        for i in range(self.len):
            ADRS.setChainAddress(i)
            ADRS.setHashAddress(0)
            sk = PRF(SK_seed, ADRS)
            tmp.append(self.chain(sk[i], 0, self.w - 1, PK_seed, ADRS))
        wotspkADRS.setType(WOTS_PK)
        wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = T_len(PK_seed, wotspkADRS, tmp)
        return pk
    
    #Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
#Output: WOTS+ signature sig
    def wots_sign(self, M, SK_seed, PK_seed, ADRS):
        csum = 0

        #  convert message to base w
        msg = base_w(M, self.w, self.len1)

        # compute checksum
        for i in range(self.len1):
            csum = csum + self.w - 1 - msg[i];
        
        # convert csum to base w
        if( (log(self.w) % 8) != 0):
            csum = csum << ( 8 - ( ( self.len2 * log(self.w) ) % 8 ));  
        
        len_2_bytes = ceil( ( self.len2 * log(self.w) ) / 8 );
        msg = concatenate( msg, base_w(toByte(csum, len_2_bytes), self.w, self.len2) )
        sig = []
        for i in range(self.len):
            ADRS.setChainAddress(i)
            ADRS.setHashAddress(0)
            sk = PRF(SK_seed, ADRS)
            sig.append(chain(sk, 0, msg[i], PK_seed, ADRS))
        return sig

#Input: Message M, WOTS+ signature sig, address ADRS, public seed PK.seed
#Output: WOTS+ public key pk_sig derived from sig
    def wots_pkFromSig(self, sig, M, PK_seed, ADRS):
        csum = 0;
        wotspkADRS = ADRS;
        
        msg = base_w(M, self.w, self.len1)
        
        # compute checksum
        for i in range(self.len1):
            csum = csum + self.w - 1 - msg[i]

        csum = csum << ( 8 - ( ( self.len2 * log(self.w) ) % 8 ))
        len_2_bytes = ceil( ( self.len2 * log(self.w) ) / 8 )
        msg = concatenate(msg, base_w(toByte(csum, len_2_bytes), self.w, self.len2))
        tmp = []
        for i in range(self.len):
            ADRS.setChainAddress(i)
            tmp.append(chain(sig[i], msg[i], self.w - 1 - msg[i], PK_seed, ADRS))

        wotspkADRS.setType(WOTS_PK);
        wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk_sig = T_len(PK_seed, wotspkADRS, tmp)
        return pk_sig
    


        

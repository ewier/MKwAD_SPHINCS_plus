'''
SPHINCS+ implementation


SPHINCS+ steps:

    Key Generation:
    Generating the SPHINCS+ private key and PK.seed requires three calls
    to a secure random number generator. Next we have to generate the top tree. For the leaves
    we need to do 2^(h/d) WOTS+ key generations (len calls to PRF for generating the sk and
    wlen calls to F for the pk) and we have to compress the WOTS+ public key (one call to Tlen).
    Computing the root of the top tree requires (2^(h/d) - 1) calls to H.

    Signing:
    For randomization and message compression we need one call to PRFmsg, and one
    to Hmsg. The FORS signature requires kt calls to PRF and F. Further, we have to compute
    the root of k binary trees of height log t which adds k(t - 1) calls to H. Finally, we need one
    call to Tk. Next, we compute one HT signature which consists of d trees similar to the key
    generation. Hence, we have to do d(2h/d) times len calls to PRF and wlen calls to F as well
    as d(2h/d) calls to Tlen. For computing the root of each tree we get additionally d(2h/d - 1)
    calls to H.

    Verification:
    First we need to compute the message hash using Hmsg. We need to do one
    FORS verification which requires k calls to F (to compute the leaf nodes from the signature
    elements), k log t calls to H (to compute the root nodes using the leaf nodes and the authentication paths), 
    and one call to Tk for hashing the roots. Next, we have to verify d XMSS
    signatures which takes < wlen calls to F and one call to Tlen each for WOTS+ signature
    verification. It also needs dh/d calls to H for the d root computations.

--------------------------------------------------------- || ----------------------------------------------------------
WOTS+

Parameters:
    n : the security parameter; it is the message length as well as the length of a private key, public key, 
        or signature element in bytes.
    w : the Winternitz parameter; it is an element of the set {4, 16, 256}

len: the number of n-byte-string elements in a WOTS+ private key, public key, and
signature


--------------------------------------------------------- || ----------------------------------------------------------
SPHINCS+ Hypertree

XMSS parameters:
    h' : the height (number of levels - 1) of the tree.
    n : the length in bytes of messages as well as of each node.
    w : the Winternitz parameter

--------------------------------------------------------- || ----------------------------------------------------------
FORS - Forest Of Random Subsets

Parameters:
    n : the security parameter; it is the length of a private key, public key, or signature
        element in bytes.
    k : the number of private key sets, trees and indices computed from the input string.
    t : the number of elements per private key set, number of leaves per hash tree and upper
        bound on the index values. The parameter t MUST be a power of 2. If t = 2^a, then the
        trees have height a and the input string is split into bit strings of length a.

Inputs to FORS are bit strings of length k log t.

'''

class Sphincs():
    '''
    n : the security parameter in bytes.
    w : the Winternitz parameter 
    h : the height of the hypertree
    d : the number of layers in the hypertree 
    k : the number of trees in FORS
    t : the number of leaves of a FORS

    m: the message digest length in bytes
    len: the number of n-byte string elements in a WOTS+ private key, public key, and signature.
    
    '''

    def spx_keygen():
        '''
        returns a SPHINCS+ key pair (SK,PK)

        '''
        pass

    def spx_sign(M, SK):
        '''
        returns a SPHINCS+ signature SIG

        M : message 
        SK : private key, SK = (SK.seed, SK.prf, PK.seed, PK.root)

        '''
        pass

    def spx_verify(M, SIG, PK):
        '''
        returns boolean value that denotes the verification of the given signature

        M : message 
        SIG : signature
        PK : public key 
        '''
        pass
    
    # 
    # WOTS+

    def chain(X, i, s, PK.seed, ADRS):
        '''
        returns value of F iterated s times on X

        X : Input string,
        i :  start index, 
        s : number of steps,
        PK.seed : public seed,
        ADRS : address

        '''
        pass

    def wots_PKgen(SK.seed, PK.seed, ADRS):
        '''
        returns WOTS+ public key pk

        SK.seed : secret seed,
        PK.seed : public seed,
        ADRS : address
        '''
        pass

    def wots_sign(M, SK.seed, PK.seed, ADRS):
        '''
        returns  WOTS+ signature sig

        M : message,
        SK.seed : secret seed,
        PK.seed : public seed,
        ADRS : address
        '''
        pass

    def wots_pkFromSig(sig, M, PK.seed, ADRS):
        '''
        returns WOTS+ public key pk_sig derived from sig

        sig : WOTS+ signature,
        PK.seed : public seed,
        ADRS : address

        
        '''
        pass

    # 
    # Hypertree
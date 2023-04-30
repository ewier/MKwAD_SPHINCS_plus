"""
SPHINCS+ implementation

"""
from utils import *
from math import floor, ceil, log
from constants import *


class Sphincs:
    """
    n : the security parameter in bytes.
    w : the Winternitz parameter
    h : the height of the hypertree
    d : the number of layers in the hypertree
    k : the number of trees in FORS
    t : the number of leaves of a FORS

    m: the message digest length in bytes
    len: the number of n-byte string elements in a WOTS+ private key, public key, and signature.

    VALUES:

    n: it is the message length as well as the length of a private key, public key, or signature element in bytes.
    w: it is an element of the set {4, 16, 256}

    """

    def __init__(self, randomise=True):
        self.n = SECURITY_PARAM
        self.w = WINTERNITZ_PARAM
        self.h = HYPERTREE_HEIGHT
        self.d = HYPERTREE_LAYERS
        self.k = FORS_TREES
        self.t = FORS_LEAVES
        self.RANDOMISE = randomise

    def spx_keygen(self):
        """
        returns a SPHINCS+ key pair (SK,PK)

        """
        SK_seed = sec_rand(self.n)
        SK_prf = sec_rand(self.n)
        PK_seed = sec_rand(self.n)
        PK_root = ht_PKgen(SK_seed, PK_seed)
        return ((SK_seed, SK_prf, PK_seed, PK_root), (PK_seed, PK_root))

    # def spx_sign(self, M, SK):
    #     '''
    #     returns a SPHINCS+ signature SIG

    #     M : message
    #     SK : private key, SK = (SK.seed, SK.prf, PK.seed, PK.root)

    #     '''
    #     SK_seed, SK_prf, PK_seed, PK_root = SK

    #     # init
    #     ADRS = self.toByte(0, 32)
    #     # generate randomizer
    #     opt = self.toByte(0, self.n)
    #     if self.RANDOMIZE:
    #         opt = self.rand(self.n)
    #     R = self.RF_msg(SK_prf, opt, M)
    #     SIG = SIG || R

    #     # compute message digest and index
    #     digest = H_msg(R, PK_seed, PK_root, M)
    #     lengths = [floor((ka +7)/ 8), floor((h - h/d +7)/ 8), floor((h/d +7)/ 8)]
    #     tmp_md, tmp_idx_tree, tmp_idx_leaf = extract_bytes(digest, lengths)
    #     md = md[:ka] # first ka bits of tmp_md
    #     idx_tree = tmp_idx_tree[:(h - h/d)] # first h - h/d bits of tmp_idx_tree
    #     idx_leaf = tmp_idx_leaf[:(h/d)] # first h/d bits of tmp_idx_leaf

    #     # FORS sign
    #     ADRS.setLayerAddress(0)
    #     ADRS.setTreeAddress(idx_tree)
    #     ADRS.setType(FORS_TREE)
    #     ADRS.setKeyPairAddress(idx_leaf)
    #     SIG_FORS = fors_sign(md, SK.seed, PK_seed, ADRS)
    #     SIG = SIG || SIG_FORS

    #     # get FORS public key
    #     PK_FORS = fors_pkFromSig(SIG_FORS, M, PK_seed, ADRS)

    #     # sign FORS public key with HT
    #     ADRS.setType(TREE)
    #     SIG_HT = ht_sign(PK_FORS, SK_seed, PK_seed, idx_tree, idx_leaf)
    #     SIG = SIG || SIG_HT
    #     return SIG

    # def spx_verify(self, M, SIG, PK):
    #     '''
    #     returns boolean value that denotes the verification of the given signature

    #     M : message
    #     SIG : signature
    #     PK : public key
    #     '''
    #     PK_seed, PK_root = PK

    #     # init
    #     ADRS = toByte(0, 32);
    #     R = SIG.getR();
    #     SIG_FORS = SIG.getSIG_FORS();
    #     SIG_HT = SIG.getSIG_HT();

    #     # compute message digest and index
    #     digest = H_msg(R, PK_seed, PK_root, M);
    #     lengths = [floor((ka +7)/ 8), floor((h - h/d +7)/ 8), floor((h/d +7)/ 8)]
    #     tmp_md, tmp_idx_tree, tmp_idx_leaf = extract_bytes(digest, lengths)
    #     md = md[:ka] # first ka bits of tmp_md
    #     idx_tree = tmp_idx_tree[:(h - h/d)] # first h - h/d bits of tmp_idx_tree
    #     idx_leaf = tmp_idx_leaf[:(h/d)] # first h/d bits of tmp_idx_leaf

    #     # compute FORS public key
    #     ADRS.setLayerAddress(0);
    #     ADRS.setTreeAddress(idx_tree);
    #     ADRS.setType(FORS_TREE);
    #     ADRS.setKeyPairAddress(idx_leaf);
    #     PK_FORS = fors_pkFromSig(SIG_FORS, md, PK_seed, ADRS);

    #     # verify HT signature
    #     ADRS.setType(TREE);
    #     return ht_verify(PK_FORS, SIG_HT, PK_seed, idx_tree, idx_leaf, PK_root);

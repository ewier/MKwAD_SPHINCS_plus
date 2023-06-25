from utils import t_ADRS
from wots import *
from math import floor, log2

class Hypertree:

    def __init__(self):
        '''
        XMSS is a method for signing a potentially large but fixed number of messages.
        It uses WOTS and a binary tree to authenticate messages.

        Each node in the binary tree is an n-byte value which is the tweakable hash of the
        concatenation of its two child nodes.
        h -> height of the tree
        nodes[0] -> root <=> public key
        '''
        self.h_prim = HYPERTREE_HEIGHT / HYPERTREE_LAYERS
        self.h = HYPERTREE_HEIGHT
        self.nodes = [0 for i in range(2**(HYPERTREE_HEIGHT+1) - 1)]
        self.d = HYPERTREE_LAYERS
        self.WOTS = WOTS()
        

    def treehash(self, SK_seed, s, z, PK_seed, ADRS):
        '''
        Input:
            Secret seed SK_seed, 
            start index s, 
            target node height z, 
            public seed PK_seed, 
            address ADRS
        Output:
            n-byte root node - top node on Stack
        '''
        if(type(z) is float):
            z = int(z)
        if (s % (1 << z)) != 0:
            return -1
        Stack = []
        for i in range(2**z):
            ADRS.setType(t_ADRS.WOTS_HASH)
            ADRS.setKeyPairAddress(s + i)
            node = self.WOTS.wots_PKgen(SK_seed, PK_seed, ADRS)
            ADRS.setType(t_ADRS.TREE)
            ADRS.setTreeHeight(1)
            ADRS.setTreeIndex(s + i)
            while (len(Stack) > 0 and ADRS.getTreeHeight() == Stack[0][1]):
                ADRS.setTreeIndex(ceil((ADRS.getTreeIndex() - 1) / 2))
                node = H(PK_seed, ADRS, concatenate(Stack.pop()[0], node))
                ADRS.setTreeHeight(ADRS.getTreeHeight() + 1)
            Stack.insert(0, (node, ADRS.getTreeHeight()))
        return Stack.pop()[0]
    
    def xmss_PKgen(self, SK_seed, PK_seed, ADRS):
        pk = self.treehash(SK_seed, 0, self.h_prim, PK_seed, ADRS)
        if(pk == -1):
            raise("TREEHASH ERROR")
        return pk
    
    def xmss_sign(self, M, SK_seed, idx, PK_seed, ADRS):
        AUTH = [0 for i in range(self.h_prim)]
        for j in range(self.h_prim):
            k = floor(idx / (2^j)) ^ 1
            AUTH[j] = self.treehash(SK_seed, k * 2**j, j, PK_seed, ADRS)
            if(AUTH[j] == -1):
                raise("PUBLIC KEY ERROR")
        ADRS.setType(t_ADRS.WOTS_HASH)
        ADRS.setKeyPairAddress(idx)
        sig = self.WOTS.wots_sign(M, SK_seed, PK_seed, ADRS)
        SIG_XMSS = concatenate(sig, AUTH)
        return SIG_XMSS
    
    def xmss_pkFromSig(self, idx, SIG_XMSS, M, PK_seed, ADRS):
        ADRS.setType(t_ADRS.WOTS_HASH)
        ADRS.setKeyPairAddress(idx)
        sig = SIG_XMSS.getWOTSSig()
        AUTH = SIG_XMSS.getXMSSAUTH()
        node_0 = self.WOTS.wots_pkFromSig(sig, M, PK_seed, ADRS)

        ADRS.setType(t_ADRS.TREE)
        ADRS.setTreeIndex(idx)
        for k in range(self.h_prim):
            ADRS.setTreeHeight(k+1)
            if (floor(idx / (2**k)) % 2) == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() / 2)
                node_1 = H(PK_seed, ADRS, concatenate(node_0, AUTH[k]))
            else:
                ADRS.setTreeIndex(ceil((ADRS.getTreeIndex() - 1) / 2))
                node_1 = H(PK_seed, ADRS, concatenate(AUTH[k], node_0))
            node_0 = node_1
        return node_0

    def ht_PKgen(self, SK_seed, PK_seed):
        '''
        Input: 
            Private seed SK_seed, 
            public seed PK_seed
        Output: 
            HT public key PK_HT
        '''
        ADRS = ADDRESS()
        ADRS.setLayerAddress(self.d-1)
        ADRS.setTreeAddress(0)
        root = self.xmss_PKgen(SK_seed, PK_seed, ADRS)
        return root

    def ht_sign(self, M, SK_seed, PK_seed, idx_tree, idx_leaf):
        '''
        Input: 
            Message M, 
            private seed SK_seed, 
            public seed PK_seed, 
            tree index idx_tree, 
            leaf index idx_leaf
        Output: 
            HT signature SIG_HT
        '''
        ADRS = ADDRESS()
        ADRS.setLayerAddress(0)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = self.xmss_sign(M, SK_seed, idx_leaf, PK_seed, ADRS)
        SIG_HT = concatenate(SIG_HT, SIG_tmp)
        root = self.xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS)
        for j in range(1, self.d):
            idx_leaf = get_n_bin_digits(idx_tree, self.h_prim)
            idx_tree = get_n_first_bin_digits(idx_tree, self.h - (j + 1) * self.h_prim)
            ADRS.setLayerAddress(j)
            ADRS.setTreeAddress(idx_tree)
            SIG_tmp = self.xmss_sign(root, SK_seed, idx_leaf, PK_seed, ADRS)
            SIG_HT = concatenate(SIG_HT, SIG_tmp)
            if j < self.d - 1:
                root = self.xmss_pkFromSig(idx_leaf, SIG_tmp, root, PK_seed, ADRS)
        return SIG_HT


def ht_verify(self, M, SIG_HT, PK_seed, idx_tree, idx_leaf, PK_HT):
    '''
    Input: 
        Message M, 
        signature SIG_HT, 
        public seed PK_seed, 
        tree index idx_tree, 
        leaf index idx_leaf, 
        HT public key PK_HT
    Output: 
        Boolean
    '''
    ADRS = ADDRESS()
    SIG_tmp = SIG_HT.getXMSSSignature(0)
    ADRS.setLayerAddress(0)
    ADRS.setTreeAddress(idx_tree)
    node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS)
    for j in range(1, self.d):
        idx_leaf = get_n_bin_digits(idx_tree, self.h_prim)
        idx_tree = get_n_first_bin_digits(idx_tree, self.h - (j + 1) * self.h_prim)
        SIG_tmp = SIG_HT.getXMSSSignature(j)
        ADRS.setLayerAddress(j)
        ADRS.setTreeAddress(idx_tree)
        node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, node, PK_seed, ADRS)
    return node == PK_HT





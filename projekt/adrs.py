from enum import Enum
from numpy import copy

class t_ADRS(Enum):
    """
    ADRS types:
     - for the hashes in WOTS+ schemes, 
     - for compression of the WOTS+ public key, 
     - for hashes within the main Merkle tree construction, 
     - for the hashes in the Merkle tree in FORS, 
     - the compression of the tree roots of FORS
     
    """
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4

class ADDRESS:
    """
    Format: ADRS is 32-bytes long (8 words 32-bits each)

     - the first seven 32-bit words set to encode the address of the chain
       (in each iteration, the address is updated to encode the current position in the chain)

    
    tree address - three words; 

    STRUCTURE:
    the first two describe position in the hypertree

    layer address - 1 word  - the height of a tree within the hypertree starting from height zero for trees on the bottom layer
    tree address  - 3 words - describes the position of a tree within a layer of a multi-tree starting with index zero for the leftmost tree
    address type  - 1 word -  set to 0 for a WOTS+ hash address, to 1 for the compression of the WOTS+ public key, to 2 for a hash tree address, to 3 for a FORS address, and to 4 for the compression of FORS tree roots
    key pair addres - 1 word - 
    chain address - 1 word - 
    hash address


    """
    def __init__(self):
        self.adrs = [0 for i in range(8)]  # 8 integers, 4 bytes each
    
    def copy(self, other):
        self.adrs = copy(other.adrs)

    def setType(self, type):
        self.adrs[4] = type.value

    def setChainAddress(self, val):
        self.adrs[6] = val

    def setHashAddress(self, val):
        self.adrs[7] = val

    def setKeyPairAddress(self, val):
        self.adrs[5] = val

    def get(self):
        return self.adrs

    def getKeyPairAddress(self):
        return self.adrs[5]

from numpy import copy

class ADDRESS:
    """
    Format: ADRS is 32-bytes long (8 words 32-bits each)

    STRUCTURE:
    the first two describe position in the hypertree

    layer address - 1 word
    tree address  - 3 words
    address type  - 1 word
    key pair addres - 1 word
    chain address - 1 word
    hash address - 1 word

    Nazwy pól zmieniają się w zależności od typu adresu.

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

    def setTreeHeight(self, val):
        self.adrs[6] = val

    def setLayerAddress(self, val):
        self.adrs[0] = val

    def setTreeAddress(self, val):
        b1 = val % 16
        b2 = (val - b1) % 16
        b3 = val - b1 - b2
        self.adrs[1] = b1
        self.adrs[2] = b2
        self.adrs[3] = b3

    def setTreeIndex(self, val):
        self.adrs[7] = val

    def get(self):
        return self.adrs

    def getKeyPairAddress(self):
        return self.adrs[5]

    def getTreeHeight(self):
        return self.adrs[6]
    
    def getTreeIndex(self):
        val = self.adrs[3]
        val += self.adrs[2] << 4
        val += self.adrs[1] << 8
        return val

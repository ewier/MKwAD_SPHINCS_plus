from sphincs import *
from wots import *
from adrs import *


class TestSphincs:
    def __init__(self, args=None):
        self.sphincs = Sphincs()

    def test_key_gen(self):
        SK, PK = self.sphincs.spx_keygen()
        return 1
    
    def test_wots(self):
        M = 'Ala ma kota'
        M = M.encode("utf-8")
        print(f"M = {M}")
        print("Step 1: WOTS init")
        wots = WOTS()
        print("Step 2: ADRS init")
        adrs = ADDRESS()
        SK_seed, PK_seed = 0, 0
        print("Step 3: KEY gen")
        sk = wots.wots_SKgen(SK_seed, adrs)
        pk = wots.wots_PKgen(SK_seed, PK_seed, adrs)
        print("Step 4: SIG gen")
        sig = wots.wots_sign(M, SK_seed, PK_seed, adrs)
        print("Step 5: PK_SIG gen")
        pk_sig = wots.wots_pkFromSig(sig, M, PK_seed, adrs)

    def test_shake(self):
        M = 'Ala ma kota'
        M = M.encode("utf-8")
        r = shake256(M)
        print(f"Result = {r}")

if __name__ == "__main__":
    T = TestSphincs()
    # print(T.test_key_gen())
    T. test_wots()
    # T.test_shake()

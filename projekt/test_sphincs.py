from sphincs import *
from wots import *
from adrs import *


class TestSphincs:
    def __init__(self, args=None):
        self.spx = Sphincs()
    
    def run_wots(self):
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

    def run_sphincs(self):
        SK, PK = self.spx.spx_keygen()
        M = 'Ala ma kota'
        M = int.from_bytes(M.encode("utf-8"), byteorder='big')
        print(f"M = {M}")
        print("Step 1: Sphincs sign")
        SIG = self.spx.spx_sign(M, SK)
        print("Step 3: Sphincs verify")
        v = self.spx.spx_verify(M, SIG, PK)
        print(f"RESULT: {v}")

    def test_shake(self):
        M = 'Ala ma kota'
        M = M.encode("utf-8")
        r = shake256(M)
        print(f"Result = {r}")

if __name__ == "__main__":
    T = TestSphincs()
    # T. run_wots()
    T.run_sphincs()
    print("TEST COMPLETE")

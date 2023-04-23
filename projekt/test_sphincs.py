from sphincs import *


class TestSphincs:
    def __init__(self, args=None):
        n, w, h, d, k, t = 1, 16, 0, 0, 0, 0
        self.sphincs = Sphincs(n, w, h, d, k, t)

    def test_key_gen(self):
        SK, PK = self.sphincs.spx_keygen()
        print(SK)
        print(PK)
        return 1


T = TestSphincs()
print(T.test_key_gen())
